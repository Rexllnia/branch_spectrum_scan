#! /usr/bin/lua

package.path = "/usr/lib/lua/?.lua;" .. package.path;

local libdbg = require("utils.debug");
local libubs = require("utils.ubus");
local libexc = require("utils.exec");
local libnet = require("utils.network");
local dkjson = require("dkjson");

-- 调试模块初始化
libdbg.debug_init("/tmp/mqtt/", "sync_rsp.lua.log", 100, libdbg.DEBUG, libdbg.OPEN);

--[[
{
    "sn":"G1NW80Q00041B",
    "id":"0000000007",
    "ts":1639916453490,
    "ack":"true",
    "data":{
        "pro":"EW1800GX-PRO",
        "mac":"30:0D:9E:0C:80:1A",
        "hwv":"1.00",
        "swv":"ReyeeOS 1.76.2417;EW_3.0(1)B11P76,Release(08241713)",
        "wmd":"ROUTER,1,1,none",
        "ip":"192.168.110.114",
        "lnid":"0",
        "lgid":"0",
        "pgid":""
    }
}
--]]
-- @sync_rsp
function sync_rsp(param)
    libdbg.lua_debug(libdbg.CRLF, "");-- 日志之前打印一个空行，不包含时间戳等信息
    libdbg.lua_debug(libdbg.INFO, "********************Enter sync_rsp()********************");

    -- 1、获取进程开关enable
local tab = {
        user = "networkId",
        bizid = "sync_networkId_0",
        ts = 0
    };
    local data = {};
    local uci = require("luci.model.uci").cursor();

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

    -- 获取networkId信息
    local str = libexc.exec_cmd_ret("dev_sta get -m networkId") or "{}";
    libdbg.lua_debug(libdbg.INFO, "str:%s", str);
    local networkId_tab = dkjson.decode(str);
    if (networkId_tab["networkId"] ~= nil and networkId_tab["groupId"] ~= nil) then
        libdbg.lua_debug(libdbg.INFO, "dev_sta get -m networkId success");
        data["lnid"] = networkId_tab["networkId"];
        data["lgid"] = networkId_tab["groupId"];
        data["pgid"] = "";
    else
        libdbg.lua_debug(libdbg.ERROR, "ubus call mqtt status failed");
        data["lnid"] = "0";
        data["lgid"] = "0";
        data["pgid"] = "";
    end

    tab["data"] = data;

    libdbg.lua_debug(libdbg.DEBUG, require("dkjson").encode(tab));
    local ubus_tab = libubs.ubus_call("mqlink", "sync_notify", tab, 3);
end

sync_rsp();