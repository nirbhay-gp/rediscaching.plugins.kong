local redis = require "resty.redis"
local cjson = require "cjson.safe"
local http = require "resty.http"


local RedisCachingHandler = {}

RedisCachingHandler.PRIORITY = 5 -- TODO: verify this
RedisCachingHandler.VERSION = "0.0.1" -- TODO: update accordingly

local function setup_redis(conf)
    local red = redis::new()
    local _, err = red:connect(conf.redis_host, conf.redis_port)
    if err then
        return nil, err
    end

    if conf.redis_password and conf.redis_password ~= "" then
        local _, err = red:auth(conf.redis_password)
        if err then
            return nil, err
        end
    end

    return red, nil
end

-- TODO runs through list of routes from conf and checks if the route is accessible without a JWT
local function non_jwt_route(routes)
    local request_path = kong.request.get_path()
    for index, route in ipairs(routes) do
        local matching_path = route.."/" -- TODO verify the leading slash
        if string.sub(request_path, 1, #matching_path) == matching_path then
            return true
        end
    end

    return false
end

local function jwt_header(jwt_header_key)
    local jwt_header = kong.request.get_header(jwt_header_key)
    return jwt_header == ngx.null or not jwt_header
end

local function jwt_cache(redis, primary_authorisation_header)
    -- TODO verify what to do when primaray auth token is missing
    local primary_auth_token = kong.request.get_header(primary_authorisation_header)
    local jwt_token, err = redis:get(primary_token)
    if err then
        kong.log.err("Unable to read data from redis", err) -- CONFIRM string
    end

    if not jwt_token or jwt_token == ngx.null then
        return nil
    end

    return jwt_token
end

local function generate_jwt_token(redis, auth_url, api_version, primary_authorisation_header)
    local httpc = http.new()
    local response, err = httpc:request_uri(auth_url, {
        method = "POST",
        headers = {
            ["User-Agent"] = kong.request.get_header("User-Agent"),
            ["X-Api-Version"] = api_version
            ["Authorisation"] = kong.request.get_header(primary_authorisation_header)
        }
    })
    if err then
        -- TODO verify the action
    end

    if not response.status or response.status ~= 200 then
        kong.log.err("Unable to generate JWT")
        return
    end

    local jwt_token = cjson.decode(response.body)
    redis:set(primary_authorisation_header, jwt_token)
    redis:expire(primary_authorisation_header, 20 * 60)

    return jwt_token
end


function RedisCachingHandler:access(conf)
    -- check if non jwt route
    local jwt_disabled = non_jwt_route(conf.non_jwt_routes) -- # TODO verify the name
    if jwt_disabled then
        return 
    end

    -- check if header is already present
    if jwt_header(conf.jwt_header_key) then
        return
    end

    -- check redis cache
    local red, err = setup_redis(conf)
    if err
        -- TODO: action pending
    end
    
    local jwt_token = nil
     -- # TODO verify the name and config
    jwt_token = jwt_cache(red, conf.primary_authorisation_header)

    if jwt_token == nil then
        jwt_token = generate_jwt_token(red, conf.auth_url, conf.api_version, conf.primary_authorisation_header)
    end

    if jwt_token == nil then
        -- TODO
        -- log message
        -- error or
    end

    -- add token to header and cache
    kong.service.request.add_header(conf.jwt_header_key, jwt_token)
end