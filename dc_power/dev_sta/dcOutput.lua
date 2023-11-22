#!/usr/bin/lua
module("dcOutput", package.seeall)
local console = require "console"
local json = require "dkjson"
local cjson = require "cjson"
local uci = require "luci.model.uci".cursor()
local cap = require "dev_cap"
local tool = require "dev.tools.common"

--dev_sta set -m dcOutput '{"func":"restart"}'
--dev_sta set -m dcOutput '{"fun":"restart"}'

--debug
local function debug(msg)
    console.debug("dcOutput", msg)
end

local function lock()
    os.execute("lock /tmp/rg_config/dcOutput.lock")
end

local function unlock()
    os.execute("lock -u /tmp/rg_config/dcOutput.lock")
end

    --从设备能力表读取供电的GPIO口
local function get_gpio_from_dev_cap()
	local data = cap.fetch("get", "dc_power").data
	if not data then
        return nil
    end
	local dc_power_cap = json.decode(data)
	local gpio_port = dc_power_cap.gpio_port
	return gpio_port
end

function module_set(param)
    lock()
    local msg
    local func
    local paramTable
    local rg_device = "/tmp/rg_device/rg_device.json"
    local dc_power_max_power = nil
    local dc_power_low_power = nil
	local gpio_port = get_gpio_from_dev_cap()
	--对gpio是否存在进行判断
	if (not gpio_port) then
		msg = "gpio port is invalid"
        debug(msg)
        unlock()
        return console.fail(msg)
	end
    --对param是否存在进行判断
    if (not param) then
        msg = "param is invalid"
        debug(msg)
        unlock()
        return console.fail(msg)
    end
    debug(param)
    --对param是否是json数据进行判断
    if (not console.is_cjson(param)) then
        msg = "param is not json"
        debug(msg)
        unlock()
        return console.fail(msg)
    end
    --对dcOutput是否存在进行判断
    paramTable = json.decode(param)
    func = paramTable.func
    if (not func) then
		func = paramTable.fun
		if (not func) then
			msg = "func is empty!"
			debug(msg)
			unlock()
			return console.fail(msg)
		end
    end
	--重启DC供电，延时设置暂定3秒
	if func == "restart" then
	    os.execute("echo 0 > /sys/class/gpio/gpio"..gpio_port.."/value")
		debug("set gpio value 0")
	    os.execute("sleep 3")
		debug("sleep 3")
	    os.execute("echo 1 > /sys/class/gpio/gpio"..gpio_port.."/value")
		debug("set gpio value 1")		
	elseif func == "stop" then
		if (tool.file_exist(rg_device) == true) then
			local file_data = tool.file_read(rg_device);
			local rg_device_json = cjson.decode(file_data);
			dc_power_max_power = rg_device_json["gateway"]["dc_power_max_power"]
		end

		if (dc_power_max_power ~= nil) then
			os.execute("echo 0 > /sys/class/gpio/gpio"..gpio_port.."/value")
			os.execute("poe_cmd debug set_max_power " .. dc_power_max_power)
		else
			debug("no dc_power_max_power, failed")
		end
	elseif func == "start" then
		if (tool.file_exist(rg_device) == true) then
			local file_data = tool.file_read(rg_device);
			local rg_device_json = cjson.decode(file_data);
			dc_power_low_power = rg_device_json["gateway"]["dc_power_low_power"]
		end

		if (dc_power_low_power ~= nil) then
			os.execute("poe_cmd debug set_max_power " .. dc_power_low_power)
			os.execute("echo 1 > /sys/class/gpio/gpio"..gpio_port.."/value")
		else
			debug("no dc_power_low_power, failed")
		end
	end
	unlock()
end