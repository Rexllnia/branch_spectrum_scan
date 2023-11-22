#! /usr/bin/lua

package.path = "/usr/lib/lua/?.lua;" .. package.path;

local libdbg = require("utils.debug");
local libubs = require("utils.ubus");
local libnet = require("utils.network");
local libfile = require("utils.file");
local dkjson = require("dkjson");

local networkid_file = "/etc/rg_config/networkid.json";
local mqtt_path = "/usr/sbin/mqtt.elf"
local uci = require("luci.model.uci").cursor();

-- 调试模块初始化
libdbg.debug_init("/tmp/rg_config/", "network_notify.lua.log", 100, libdbg.DEBUG, libdbg.OPEN);

--[[
{
    "sn":"G1NW80Q00041B",
    "id":"0000000007",
    "ts":1639916453490,
    "ack":"true",
    "data":{
        "pro":"EW1800GX-PRO",
        "mac":"300d,9e0c,801a",
        "hwv":"1.00",
        "swv":"ReyeeOS 1.76.2417;EW_3.0(1)B11P76,Release(08241713)",
        "wmd":"ROUTER,1,1,none",
        "ip":"192.168.110.114",
        "lnid":"0",
        "lgid":"0",
        "pgid":"",
        "mastersn":"G1NW80Q00041B",
        "status":"CONFLICT"
    }
}
--]]
-- @mqlink_sync
function mqlink_sync()
    libdbg.lua_debug(libdbg.CRLF, "");-- 日志之前打印一个空行，不包含时间戳等信息
    libdbg.lua_debug(libdbg.INFO, "********************Enter mqlink_sync()********************");

    local tab = {
        user = "SON",
        bizid = "syn_SON_0",
        ack = "true",
        ts = os.time();
    };

    local data = {};

    -- 获取sysinfo信息
    local val = uci:get_first("sysinfo", "sysinfo", "product_class");
    if (val == nil) then
        libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].product_class failed");
        val = "UNKOWN";
    end
    libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].product_class=%s", val);
    data["pro"] = val;

    val = uci:get_first("sysinfo", "sysinfo", "sys_mac");
    if (val == nil) then
        libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].sys_mac failed");
        val = "";
    end
    libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].sys_mac=%s", val);
    local ret, mac_dot = libnet.mac_to_dot(val);
    if (ret == false) then
        libdbg.lua_debug(libdbg.INFO, "libnet.mac_to_dot() failed");
    end
    data["mac"] = mac_dot;

    val = uci:get_first("sysinfo", "sysinfo", "hardware_version");
    if (val == nil) then
        libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].hardware_version failed");
        val = "";
    end
    libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].hardware_version=%s", val);
    data["hwv"] = val;

    val = uci:get_first("sysinfo", "sysinfo", "software_version");
    if (val == nil) then
        libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].software_version failed");
        val = "";
    end
    libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].software_version=%s", val);
    data["swv"] = val;

    val = uci:get_first("sysinfo", "sysinfo", "forwardMode");
    if (val == nil) then
        libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].forwardMode failed");
        val = "";
    end
    libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].forwardMode=%s", val);
    data["wmd"] = val;

    val = uci:get_first("sysinfo", "sysinfo", "autoJoin");
    if (val == nil) then
        libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].autoJoin failed");
        val = "";
    end
    libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].autoJoin=%s", val);
    data["wmd"] = data["wmd"]..","..(val == "true" and "1" or "0");

    val = uci:get_first("sysinfo", "sysinfo", "acEnable");
    if (val == nil) then
        libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].acEnable failed");
        val = "";
    end
    libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].acEnable=%s", val);
    data["wmd"] = data["wmd"]..","..(val == "true" and "1" or "0");

    val = uci:get_first("sysinfo", "sysinfo", "relayMode");
    if (val == nil) then
        libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].relayMode failed");
        val = "";
    end
    libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].relayMode=%s", val);
    data["wmd"] = data["wmd"]..","..val;

    val = uci:get_first("sysinfo", "sysinfo", "wan_ip");
    if (val == nil) then
        libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].wan_ip failed");
        val = "";
    end
    libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].wan_ip=%s", val);
    data["ip"] = val;

    val = uci:get_first("sysinfo", "sysinfo", "serial_num");
    if (val == nil) then
        libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].serial_num failed");
        val = "";
    end
    libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].serial_num=%s", val);
    data["mastersn"] = val;

    -- 获取networkid信息
    if (libfile.file_is_exist(networkid_file) == true) then
        libdbg.lua_debug(libdbg.INFO, "%s is exist", networkid_file);

        local file_data = libfile.read_file(networkid_file);
        local json_tab = dkjson.decode(file_data);

        -- 解析参数：networkId
        if (json_tab["networkId"] ~= nil) then
            data["lnid"] = json_tab["networkId"];
        else
            data["lnid"] = "";
        end

        -- 解析参数：groupId
        if (json_tab["groupId"] ~= nil) then
            data["lgid"] = json_tab["groupId"];
        else
            data["lgid"] = "";
        end

        -- 解析参数：parentGroupId
        if (json_tab["parentGroupId"] ~= nil) then
            data["pgid"] = json_tab["parentGroupId"];
        else
            data["pgid"] = "";
        end
    else
        data["lnid"] = "";
        data["lgid"] = "";
        data["pgid"] = "";
    end

    data["status"] = "CONNECT";

    tab["data"] = data;

    libdbg.lua_debug(libdbg.DEBUG, require("dkjson").encode(tab));
    local ubus_tab = libubs.ubus_call("mqlink", "sync_notify", tab, 3);
end

--[[
{
    "user":"SON",
    "name":"SON",
    "bizid":"sta_SON_0",
    "ts":123,
    "ack":"true",
    "val":{
        "lnid":"0",
        "lgid":"0",
        "pgid":"1",
        "mastersn":"G1NW322000127",
        “status”:"<UKNOWN|CONNECT|CONFLICT>"
    }
}
--]]
-- @mqlink_notify
function mqlink_notify()
    libdbg.lua_debug(libdbg.CRLF, "");-- 日志之前打印一个空行，不包含时间戳等信息
    libdbg.lua_debug(libdbg.INFO, "********************Enter mqlink_notify()********************");

    local tab = {
        user = "SON",
        bizid = "sta_SON_0",
        name = "SON",
        ack = "true",
        ts = os.time();
    };

    local data = {};
    -- 获取networkid信息
    if (libfile.file_is_exist(networkid_file) == true) then
        libdbg.lua_debug(libdbg.INFO, "%s is exist", networkid_file);

        local file_data = libfile.read_file(networkid_file);
        local json_tab = dkjson.decode(file_data);

        -- 解析参数：networkId
        if (json_tab["networkId"] ~= nil) then
            data["lnid"] = json_tab["networkId"];
        else
            data["lnid"] = "";
        end

        -- 解析参数：groupId
        if (json_tab["groupId"] ~= nil) then
            data["lgid"] = json_tab["groupId"];
        else
            data["lgid"] = "";
        end

        -- 解析参数：parentGroupId
        if (json_tab["parentGroupId"] ~= nil) then
            data["pgid"] = json_tab["parentGroupId"];
        else
            data["pgid"] = "";
        end
    else
        data["lnid"] = "";
        data["lgid"] = "";
        data["pgid"] = "";
    end

    val = uci:get_first("sysinfo", "sysinfo", "serial_num");
    if (val == nil) then
        libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].serial_num failed");
        val = "";
    end
    libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].serial_num=%s", val);
    data["mastersn"] = val;

    data["status"] = "CONNECT";

    tab["val"] = data;

    libdbg.lua_debug(libdbg.DEBUG, require("dkjson").encode(tab));
    local ubus_tab = libubs.ubus_call("mqlink", "status_notify", tab, 3);
end

-- *******************main*******************
-- 存在mqtt则无需启动
if (libfile.file_is_exist(mqtt_path) == true) then
    libdbg.lua_debug(libdbg.INFO, "mqtt.elf is exist, no need call mqlink sync|notify", val);
    os.exit()
end

-- 非网桥设备则无需启动
local val = uci:get_first("sysinfo", "sysinfo", "dev_type");
if (val == nil) then
    libdbg.lua_debug(libdbg.INFO, "uci get sysinfo.@sysinfo[0].dev_type failed");
    os.exit()
end
if (val ~= "est") then
    libdbg.lua_debug(libdbg.INFO, "device type is %s, no need call mqlink sync|notify", val);
    os.exit()
end

-- 入参判断
if (arg[1] == nil) then
    libdbg.lua_debug(libdbg.INFO, "failed to get param, param is empty");
    os.exit()
end
if (arg[1] ~= "sync" and arg[1] ~= "notify") then
    libdbg.lua_debug(libdbg.INFO, "param : %s is invalid, request sync|notify", arg[1]);
    os.exit()
end
libdbg.lua_debug(libdbg.INFO, "ready to call mqlink %s", arg[1]);

if (arg[1] == "sync") then
    mqlink_sync();
elseif (arg[1] == "notify") then
    mqlink_notify();
end