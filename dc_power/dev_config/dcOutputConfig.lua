#!/usr/bin/lua
module("dcOutputConfig", package.seeall)

--*************************以下为加载库**************************
local console = require "console"
local json = require "dkjson"
local cjson = require "cjson"
local uci = require "luci.model.uci".cursor()
local cap = require "dev_cap"

--dev_config set -m dcOutputConfig '{"enable":"1"}'

local function debug(msg)
    console.debug("dcOutputConfig", msg)
end

local function lock()
    os.execute("lock /tmp/rg_config/dcOutputConfig.lock")
end

local function unlock()
    os.execute("lock -u /tmp/rg_config/dcOutputConfig.lock")
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

    --默认设置使能DC供电
function module_default_config_get()
	local default_config = '{"enable":"1"}'
	return default_config
end

function module_set(param)
    lock()
    local msg
    local enable
    local paramTable
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
    --对dcOutputConfig是否存在进行判断
    paramTable = json.decode(param)
    enable = paramTable.enable
    if (not enable) then
	msg = "enable is empty!"
        debug(msg)
        unlock()
        return console.fail(msg)
    end
	
    --判断GPIO2的节点是否存在，没有的则创建节点	
	if console.is_file_exist("/sys/class/gpio/gpio"..gpio_port.."/value") then
		os.execute("echo out > /sys/class/gpio/gpio"..gpio_port.."/direction")
	else
		os.execute("echo "..gpio_port.."> /sys/class/gpio/export")
		os.execute("echo out > /sys/class/gpio/gpio"..gpio_port.."/direction")
	end
	
    --根据参数选择使能或者禁用DC供电	
	if enable == "0" then
	    os.execute("echo 0 > /sys/class/gpio/gpio"..gpio_port.."/value")
	elseif enable == "1" then
	    os.execute("echo 1 > /sys/class/gpio/gpio"..gpio_port.."/value") 
    end
	unlock()
end