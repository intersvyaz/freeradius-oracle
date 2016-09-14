#include <stdbool.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <oci.h>

#include "vector.h"

#define MOD_OCI_SUCCESS(x) (((x) == OCI_SUCCESS) || ((x) == OCI_SUCCESS_WITH_INFO))

enum {
  RLM_ORACLE_GET,
  RLM_ORACLE_SET
};

typedef struct rlm_oracle_bind_pair {
  const char *name;
  size_t name_len;
  vp_tmpl_t *value;
} rlm_oracle_bind_pair_t;

typedef struct rlm_oracle_column {
  OCIDefine *def;
  char value[MAX_STRING_LEN + 1];
  sb2 indicator;
  ub2 retcode;
  ub2 retlen;
} rlm_oracle_column_t;

typedef struct rlm_oracle_commit {
  bool auto_flag;
  uint32_t query_thresh;
  uint32_t time_thresh;
} rlm_oracle_commit_t;

typedef struct rlm_oracle {
  struct {
    const char *action;
    const char *dbname;
    const char *dbuser;
    const char *dbpass;
    const char *query;
    vec(rlm_oracle_bind_pair_t) bind_pairs;
    uint32_t attr_column;
    uint32_t value_column;
    rlm_oracle_commit_t commit;
  } cfg;

  const char *name;
  int action;
  size_t query_len;
  OCIEnv *env;
  fr_connection_pool_t *pool;
} rlm_oracle_t;

typedef struct rlm_oracle_conn {
  rlm_oracle_commit_t *commit;
  struct timeval last_commit;
  uint64_t queries_executed;
  bool alive;

  OCIError *err;
  OCISvcCtx *svc;
  OCIServer *server;
  OCIStmt *stmt;
  ub4 stmt_type;
  OCIBind **binds;
} rlm_oracle_conn_t;

static const CONF_PARSER module_config[] = {
    {"action",
     FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_oracle_t, cfg.action), NULL},
    {"dbname",
     FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_oracle_t, cfg.dbname), NULL},
    {"dbuser",
     FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_oracle_t, cfg.dbuser), NULL},
    {"dbpass", // allow empty password
     FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, rlm_oracle_t, cfg.dbpass), ""},
    {"query",
     FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_oracle_t, cfg.query), NULL},
    {"attr_column",
     FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_oracle_t, cfg.attr_column), "0"},
    {"value_column",
     FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_oracle_t, cfg.value_column), "0"},
    {"autocommit",
     FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_oracle_t, cfg.commit.auto_flag), "yes"},
    {"commit_query_thresh",
     FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_oracle_t, cfg.commit.query_thresh), "0"},
    {"commit_time_thresh",
     FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_oracle_t, cfg.commit.time_thresh), "0"},
    CONF_PARSER_TERMINATOR
};

/**
 * Return human readable OCI error.
 * @param[in] code Error code.
 * @param[in] handle Handle pointer.
 * @param[in] htype Handle type.
 * @return String representation of error.
 */
static const char *mod_strerror(sword code, void *handle, ub4 htype) {
  static __thread char errmsg[OCI_ERROR_MAXMSG_SIZE2];

  if (handle) {
    sb4 errcode;
    if (OCIErrorGet(handle, 1, NULL, &errcode, (OraText *) errmsg, sizeof(errmsg), htype) == OCI_SUCCESS) {
      return errmsg;
    }
  }

  switch (code) {
    case OCI_SUCCESS:
      return "OCI_SUCCESS";
    case OCI_SUCCESS_WITH_INFO:
      return "OCI_SUCCESS_WITH_INFO";
    case OCI_NEED_DATA:
      return "OCI_NEED_DATA";
    case OCI_NO_DATA:
      return "OCI_NO_DATA";
    case OCI_ERROR:
      return "OCI_ERROR";
    case OCI_INVALID_HANDLE:
      return "OCI_INVALID_HANDLE";
    case OCI_STILL_EXECUTING:
      return "OCI_STILL_EXECUTING";
    case OCI_CONTINUE:
      return "OCI_CONTINUE";
    default:
      return "UNKNOWN";
  }
}

/**
 * Wrapper for OCIEnv error string retrieving.
 * @param[in] code Error code.
 * @param[in] env OCIEnv handle.
 * @return Erorr string.
 */
static inline const char *mod_strerror_env(sword code, OCIEnv *env) {
  return mod_strerror(code, env, OCI_HTYPE_ENV);
}

/**
 * Wrapper for OCIError error string retrieving.
 * @param[in] code Error code.
 * @param[in] err OCIError handle.
 * @return Erorr string.
 */
static inline const char *mod_strerror_err(sword code, OCIError *err) {
  return mod_strerror(code, err, OCI_HTYPE_ERROR);
}

/**
 * Detach module.
 * @param[in] instance Instance handle.
 * @return Zero on success.
 */
static int mod_detach(void *instance) {
  rlm_oracle_t *inst = instance;

  fr_connection_pool_free(inst->pool);

  if (inst->env) {
    OCIHandleFree(inst->env, OCI_HTYPE_ENV);
    // do not call OCITerminate as other instances can be still working
  }

  // member 'value' of each element will be freed by talloc
  vec_free(inst->cfg.bind_pairs);

  return 0;
}

/**
 * Perform commit on connection if one of the thresholds is reached.
 * @param[in] conn Connection handle.
 * @return True on success.
 */
static bool mod_conn_commit(rlm_oracle_conn_t *conn) {
  if (conn->commit->auto_flag) {
    return true;
  }

  if (!conn->alive) {
    return false;
  }

  struct timeval now = {0}, diff = {0};
  bool need_commit = false;

  if (conn->commit->time_thresh) {
    gettimeofday(&now, NULL);
    timersub(&now, &conn->last_commit, &diff);
    need_commit = (diff.tv_sec >= conn->commit->time_thresh);
  }

  if (!need_commit && conn->commit->query_thresh) {
    need_commit = (conn->queries_executed >= conn->commit->query_thresh);
    if (need_commit) {
      gettimeofday(&now, NULL);
      if (DEBUG_ENABLED) timersub(&now, &conn->last_commit, &diff);
    }
  }

  if (need_commit) {
    DEBUG("rlm_oracle: committing %zu queries after %ld.%ld seconds",
          conn->queries_executed, diff.tv_sec, diff.tv_usec);

    sword code = OCITransCommit(conn->svc, conn->err, OCI_DEFAULT);
    if (!MOD_OCI_SUCCESS(code)) {
      ERROR("rlm_oracle: commit failed: %s", mod_strerror_err(code, conn->err));
      conn->alive = false;
      return false;
    }

    conn->last_commit = now;
    conn->queries_executed = 0;
  }

  return true;
}

/**
 * Module connection destructor.
 * @param[in] conn Connection handle.
 * @return Zero on success.
 */
static int mod_conn_free(rlm_oracle_conn_t *conn) {
  // force commit
  OCITransCommit(conn->svc, conn->err, OCI_DEFAULT);
  OCIStmtRelease(conn->stmt, conn->err, NULL, 0, OCI_DEFAULT);
  // conn->server is extracted from svc and freed automatically
  OCILogoff(conn->svc, conn->err);
  OCIHandleFree(conn->err, OCI_HTYPE_ERROR);
  DEBUG("rlm_oracle: closed connection");
  return 0;
}

/**
 * Module connection constructor.
 * @param[in] ctx Talloc context.
 * @param[in] instance Module instance.
 * @return NULL on error, else a connection handle.
 */
static void *mod_conn_create(TALLOC_CTX *ctx, void *instance) {
  rlm_oracle_t *inst = instance;
  rlm_oracle_conn_t conn = {0};
  sword code = OCI_SUCCESS;

  code = OCIHandleAlloc(inst->env, (void **) &conn.err, OCI_HTYPE_ERROR, 0, 0);
  if (!MOD_OCI_SUCCESS(code)) {
    ERROR("rlm_oracle (%s): failed to allocate OCI error handle: %s", inst->name, mod_strerror_env(code, inst->env));
    goto error;
  }

  code = OCILogon2(inst->env, conn.err, &conn.svc,
                   (const OraText *) inst->cfg.dbuser, (ub4) strlen(inst->cfg.dbuser),
                   (const OraText *) inst->cfg.dbpass, (ub4) strlen(inst->cfg.dbpass),
                   (const OraText *) inst->cfg.dbname, (ub4) strlen(inst->cfg.dbname),
                   OCI_DEFAULT);
  if (!MOD_OCI_SUCCESS(code)) {
    ERROR("rlm_oracle (%s): failed to connect to %s@%s: %s",
          inst->name, inst->cfg.dbuser, inst->cfg.dbname, mod_strerror_err(code, conn.err));
    goto error;
  }

  code = OCIAttrGet(conn.svc, OCI_HTYPE_SVCCTX, &conn.server, NULL, OCI_HTYPE_SERVER, conn.err);
  if (!MOD_OCI_SUCCESS(code)) {
    ERROR("rlm_oracle (%s): failed to get server handle from service context: %s",
          inst->name, mod_strerror_err(code, conn.err));
    goto error;
  }

  code = OCIStmtPrepare2(conn.svc, &conn.stmt, conn.err,
                         (OraText *) inst->cfg.query, (ub4) inst->query_len,
                         NULL, 0, OCI_NTV_SYNTAX, OCI_DEFAULT);
  if (!MOD_OCI_SUCCESS(code)) {
    ERROR("rlm_oracle (%s): failed to prepare OCI statement: %s", inst->name, mod_strerror_err(code, conn.err));
    goto error;
  }

  code = OCIAttrGet(conn.stmt, OCI_HTYPE_STMT, &conn.stmt_type, 0, OCI_ATTR_STMT_TYPE, conn.err);
  if (!MOD_OCI_SUCCESS(code)) {
    ERROR("rlm_oracle (%s): failed to get OCI statement type: %s", inst->name, mod_strerror_err(code, conn.err));
    return false;
  }

  conn.alive = true;
  conn.commit = &inst->cfg.commit;
  conn.binds = talloc_zero_array(ctx, OCIBind*, (unsigned) vec_len(inst->cfg.bind_pairs));
  gettimeofday(&conn.last_commit, NULL);

  rlm_oracle_conn_t *real_conn = talloc_memdup(ctx, &conn, sizeof(conn));
  talloc_set_destructor(real_conn, mod_conn_free);

  return real_conn;

  error:
  if (conn.stmt) OCIStmtRelease(conn.stmt, conn.err, NULL, 0, OCI_DEFAULT);
  if (conn.svc) OCILogoff(conn.svc, conn.err);
  if (conn.err) OCIHandleFree(conn.err, OCI_HTYPE_ERROR);
  return NULL;
}

/**
 * Check is connection alive.
 * @param[in] instance
 * @param[in] connection
 * @return < 0 on error or if the connection is unusable, else 0.
 */
static int mod_conn_alive(void *instance, void *connection) {
  (void) instance;
  rlm_oracle_conn_t *conn = connection;

  if (!conn->alive) {
    return -1;
  }

  ub4 status = OCI_SERVER_NOT_CONNECTED;
  sword code = OCIAttrGet(conn->server, OCI_HTYPE_SERVER, &status, NULL, OCI_ATTR_SERVER_STATUS, conn->err);
  if (code != OCI_SUCCESS || status != OCI_SERVER_NORMAL) {
    return -1;
  }

  if (!mod_conn_commit(conn)) {
    return -1;
  }

  return 0;
}

/**
 * Initialize module instance.
 * @param[in] conf Module config.
 * @param[in] instance Module instance.
 * @return -1 if instantiation failed, else 0.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance) {
  rlm_oracle_t *inst = instance;
  bool ok = true;

  inst->query_len = strlen(inst->cfg.query);

  inst->name = cf_section_name2(conf);
  if (!inst->name) {
    inst->name = cf_section_name1(conf);
  }

  if (!strcasecmp(inst->cfg.action, "get")) {
    inst->action = RLM_ORACLE_GET;
  } else if (!strcasecmp(inst->cfg.action, "set")) {
    inst->action = RLM_ORACLE_SET;
  } else {
    cf_log_err_cp(cf_pair_find(conf, "action"), "invalid option 'action', use 'get' or 'set'");
    ok = false;
  }

  if (!inst->cfg.commit.auto_flag) {
    if (!inst->cfg.commit.query_thresh && !inst->cfg.commit.time_thresh) {
      WARN("rlm_oracle (%s): 'autocommit is disabled and no thresholds are set!", inst->name);
    }
  }

  CONF_SECTION *conf_bind = cf_section_sub_find(conf, "bind");
  if (conf_bind) {
    CONF_ITEM *cf_item = NULL;
    while ((cf_item = cf_item_find_next(conf_bind, cf_item)) != NULL) {
      if (!cf_item_is_pair(cf_item)) {
        const char *item_name = cf_section_name1(cf_item_to_section(cf_item));
        cf_log_err_cs(conf, "invalid bind pair %s", item_name);
        ok = false;
        continue;
      }

      CONF_PAIR *cf_pair = cf_item_to_pair(cf_item);
      rlm_oracle_bind_pair_t *bind_pair = talloc(inst, rlm_oracle_bind_pair_t);
      bind_pair->name = cf_pair_attr(cf_pair);
      bind_pair->name_len = strlen(bind_pair->name);

      const char *value_str = cf_pair_value(cf_pair);
      ssize_t value_len = tmpl_afrom_str(inst, &bind_pair->value,
                                         value_str, strlen(value_str), cf_pair_value_type(cf_pair),
                                         REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
      if (value_len <= 0) {
        cf_log_err_cp(cf_pair, "invalid bind pair value");
        ok = false;
        continue;
      }
      vec_push_back(inst->cfg.bind_pairs, bind_pair);
    }
  }

  sword code = OCIEnvCreate(&inst->env, OCI_THREADED | OCI_NEW_LENGTH_SEMANTICS, 0, 0, 0, 0, 0, 0);
  if (!MOD_OCI_SUCCESS(code)) {
    ERROR("rlm_oracle (%s): failed to create OCI environment: %s", inst->name, mod_strerror_env(code, NULL));
    ok = false;
  } else {
    if (!cf_section_sub_find(conf, "pool")) {
      ERROR("rlm_oracle (%s): pool referencing is forbidden", inst->name);
      ok = false;
    } else {
      inst->pool = fr_connection_pool_module_init(conf, inst, mod_conn_create, mod_conn_alive, inst->name);
      if (!inst->pool) {
        ok = false;
      }
    }
  }

  if (!ok) mod_detach(inst);
  return ok ? 0 : -1;
}

/**
 * Prepare oracle request.
 * @param[in] conn Connection handle.
 * @param[in] inst Module instance.
 * @param[in] request Radius request.
 * @return True on success.
 */
static bool mod_conn_stmt_bind(rlm_oracle_t *inst, REQUEST *request, rlm_oracle_conn_t *conn) {
  for (size_t i = 0; i < vec_len(inst->cfg.bind_pairs); i++) {
    rlm_oracle_bind_pair_t *bpair = &vec_elt(inst->cfg.bind_pairs, i);

    char *value = NULL;
    ssize_t value_len = tmpl_aexpand(request, &value, request, bpair->value, NULL, NULL);
    if (value_len < 0) {
      RERROR("failed to substitute bind pair '%s' => '%s'", bpair->name, bpair->value->name);
      return false;
    }

    RDEBUG2("binding '%s' => '%s'", bpair->name, value);
    // first call will allocate bind handle, next calls will reuse this handle
    sword code = OCIBindByName(conn->stmt, &conn->binds[i], conn->err,
                               (const OraText *) bpair->name, (sb4) bpair->name_len,
                               value, (sb4) (value_len + 1), // OCI wants null terminator
                               SQLT_STR, NULL, NULL, NULL, 0, NULL, OCI_DEFAULT);
    if (!MOD_OCI_SUCCESS(code)) {
      RERROR("failed to bind %s to OCI statement: %s", bpair->name, mod_strerror_err(code, conn->err));
      return false;
    }
  }

  return true;
}

/**
 * Execute oracle request.
 * @param[in] conn Connection handle.
 * @param[in] request Radius request.
 * @return True on success.
 */
static bool mod_conn_stmt_execute(rlm_oracle_conn_t *conn, REQUEST *request) {
  ub4 iters = (conn->stmt_type == OCI_STMT_SELECT) ? 0 : 1;
  ub4 mode = conn->commit->auto_flag ? OCI_COMMIT_ON_SUCCESS : OCI_DEFAULT;

  sword code = OCIStmtExecute(conn->svc, conn->stmt, conn->err, iters, 0, NULL, NULL, mode);
  if (!MOD_OCI_SUCCESS(code)) {
    RERROR("failed to execute OCI statement: %s", mod_strerror_err(code, conn->err));
    return false;
  } else if (code == OCI_SUCCESS_WITH_INFO) {
    RWARN("executed query with warning: %s", mod_strerror_err(code, conn->err));
  }

  return true;
}

/**
 * Fetch data from oracle request.
 * @param[in] conn Connection handle.
 * @param[in] attr_col Attribute column index.
 * @param[in] value_col Value column index.
 * @param[in] request Radius request.
 * @param[in,out] found Found flag.
 * @return Number of fetched records, -1 on error.
 */
static int mod_conn_stmt_fetch(rlm_oracle_conn_t *conn, size_t attr_col, size_t value_col, REQUEST *request) {
  ub4 col_count = 0;

  sword code = OCIAttrGet((dvoid *) conn->stmt, OCI_HTYPE_STMT, &col_count, 0, OCI_ATTR_PARAM_COUNT, conn->err);
  if (!MOD_OCI_SUCCESS(code)) {
    RERROR("failed to get OCI column count: %s", mod_strerror_err(code, conn->err));
    return -1;
  }

  if (attr_col >= col_count) {
    RERROR("attribute column index out of query columns bounds (%zu >= %u)", attr_col, col_count);
    return -1;
  }

  if (value_col >= col_count) {
    RERROR("value column index out of query columns bounds (%zu >= %u)", value_col, col_count);
    return -1;
  }

  rlm_oracle_column_t *cols = talloc_zero_array(request, rlm_oracle_column_t, col_count);
  for (ub4 i = 0; i < col_count; i++) {
    // zero column is ROWID, skip it
    code = OCIDefineByPos(conn->stmt, &cols[i].def, conn->err, i + 1,
                          cols[i].value, sizeof(cols[i].value), SQLT_CHR,
                          &cols[i].indicator, &cols[i].retlen, &cols[i].retcode, OCI_DEFAULT);
    if (!MOD_OCI_SUCCESS(code)) {
      RERROR("failed to define buffer for OCI column %u: %s", i + 1, mod_strerror_err(code, conn->err));
      return -1;
    }
  }

  int rows_count = 0;
  for (;;) {
    code = OCIStmtFetch2(conn->stmt, conn->err, 1, OCI_FETCH_NEXT, 1, OCI_DEFAULT);
    if (code == OCI_NO_DATA) {
      break;
    } else if (!MOD_OCI_SUCCESS(code)) {
      RERROR("failed to fetch next row: %s", mod_strerror_err(code, conn->err));
      return -1;
    }

    cols[attr_col].value[cols[attr_col].retlen] = '\0';

    if (attr_col == value_col) {
      FR_TOKEN ret_token = fr_pair_list_afrom_str(request->reply, cols[attr_col].value, &request->reply->vps);
      if (ret_token == T_INVALID) {
        RWARN("failed to parse list of VPs '%s', will try to parse manually as a single VP", cols[attr_col].value);
        char *attr_str = cols[attr_col].value;
        char *value_str = strchr(attr_str, '=');
        if (value_str) {
          value_str[0] = '\0';
          value_str++;
          VALUE_PAIR *new_vp = fr_pair_make(request->reply, &request->reply->vps, attr_str, value_str, T_OP_ADD);
          if (!new_vp) {
            RWARN("failed to parse VP: %s = %s", attr_str, value_str);
          } else {
            RDEBUG("fetched %s = %s", attr_str, value_str);
          }
        } else {
          RWARN("failed to parse manually, '=' sign not found at VP: %s", attr_str);
        }
      } else {
        RDEBUG("fetched VP list: %s", cols[attr_col].value);
      }
    } else {
      cols[value_col].value[cols[value_col].retlen] = '\0';
      RDEBUG("fetched %s = %s", cols[attr_col].value, cols[value_col].value);
      VALUE_PAIR *new_vp = fr_pair_make(request->reply, &request->reply->vps,
                                        cols[attr_col].value, cols[value_col].value, T_OP_ADD);
      if (!new_vp) {
        RWARN("failed to parse VP: %s = %s", cols[attr_col].value, cols[value_col].value);
      }
    }
    rows_count++;
  }

  return rows_count;
}

/**
 * Module main procedure.
 * @param[in] instance Module instance.
 * @param[in] request Radius request.
 * @return One of #rlm_rcode_t codes.
 */
static rlm_rcode_t mod_proc(void *instance, REQUEST *request) {
  rlm_oracle_t *inst = instance;
  rlm_oracle_conn_t *conn = NULL;
  rlm_rcode_t code = RLM_MODULE_FAIL;

  conn = fr_connection_get(inst->pool);

  if (conn) {
    if (mod_conn_stmt_bind(inst, request, conn)) {
      if (mod_conn_stmt_execute(conn, request)) {
        if (inst->action == RLM_ORACLE_GET) {
          int rows_count = mod_conn_stmt_fetch(conn, inst->cfg.attr_column, inst->cfg.value_column, request);

          if (rows_count == 0) {
            code = RLM_MODULE_NOTFOUND;
          } else if (rows_count > 0) {
            code = RLM_MODULE_UPDATED;
          }
        } else {
          code = RLM_MODULE_OK;
        }
      }
    }
  }

  if (conn) {
    conn->queries_executed++;
    mod_conn_commit(conn);
    fr_connection_release(inst->pool, conn);
  }

  return code;
}

// globally exported name
extern module_t rlm_oracle;
module_t rlm_oracle = {
    .magic = RLM_MODULE_INIT,
    .name = "oracle",
    .type = RLM_TYPE_THREAD_SAFE | RLM_TYPE_HUP_SAFE,
    .inst_size = sizeof(rlm_oracle_t),
    .config = module_config,
    .bootstrap = NULL,
    .instantiate = mod_instantiate,
    .detach = mod_detach,
    .methods ={
        [MOD_AUTHENTICATE] = mod_proc,
        [MOD_AUTHORIZE] = mod_proc,
        [MOD_PREACCT] = mod_proc,
        [MOD_ACCOUNTING] = mod_proc,
        [MOD_SESSION] = NULL,
        [MOD_PRE_PROXY] = mod_proc,
        [MOD_POST_PROXY] = mod_proc,
        [MOD_POST_AUTH] = mod_proc,
#ifdef WITH_COA
        [MOD_RECV_COA] = mod_proc,
        [MOD_SEND_COA] = mod_proc,
#endif
    },
};
