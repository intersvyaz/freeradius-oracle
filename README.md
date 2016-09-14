# FreeRADIUS 3.x Oracle module

Simple module for performing Oracle SQL queries.

### Usage examples

```
oracle oracle_select_example {
    # Perform select query
    action = get
    
    # Database name
    dbname = MAIN
    
    # User name
    dbuser = scott
    
    # User password
    dbpass = tiger
    
    # Thread pool configuration
    pool {
        start = ${thread[pool].start_servers}
        min = ${thread[pool].min_spare_servers}
        max = ${thread[pool].max_servers}
        spare = ${thread[pool].max_spare_servers}
        uses = 0
        lifetime = 0
        idle_timeout = 60
    }
    
    # Query (support attributes substitution)
    query = "select * from table where id = :id and value = :value"
    
    # Bind variables (support attributes substitution)
    bind {
        id = &Calling-Station-Id
        value = &User-Name
    }
    
    # Attribute name column index (optional, default is 0)
    # When both `attr_column` and `value_column` are same then 
    # this column is interpreted as a sequense of `'attr'='value'` pairs.
    attr_column = 0
    
    # Value column index (optional, default is 0)
    value_column = 1
    
    # Enable commit after each query (optional, default is "yes")
    autocommit = no
    
    # Perform commit every N-th queries (optional, default is 0) 
    commit_query_thresh = 0
    
    # Preform commit every N-th seconds (optional, default is 0)
    commit_time_thresh = 0
}

oracle oracle_insert_example {
    # Preform insert
    action = set
    
    # Database name
    dbname = MAIN
    
    # User name
    dbuser = scott
    
    # User password
    dbpass = tiger
    
    # Thread pool configuration
    pool {
        start = ${thread[pool].start_servers}
        min = ${thread[pool].min_spare_servers}
        max = ${thread[pool].max_servers}
        spare = ${thread[pool].max_spare_servers}
        uses = 0
        lifetime = 0
        idle_timeout = 60
    }
    
    # Query (support attributes substitution)
    query = "insert into table(id, value) VALUES(:id, :value)"
    
    # Bind variables (support attributes substitution)
    bind {
        id = &Calling-Station-Id
        value = &User-Name
    }
    
    # Enable commit after each query (optional, default is "yes")
    autocommit = no
    
    # Perform commit every N-th queries (optional, default is 0) 
    commit_query_thresh = 100
    
    # Preform commit every N-th seconds (optional, deffault is 0)
    commit_time_thresh = 5
}
```
