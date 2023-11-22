#
# Copyright (C) 2006-2012 OpenWrt.org
# Copyright (C) 2010 Vertical Communications
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(TOPDIR)/.config

PKG_NAME:=rg-tipc-msg-est
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

ifeq ($(CONFIG_PACKAGE_fredis), y)
export CONFIG_REDIS_SUPPORT := y
endif

define Package/$(PKG_NAME)
  SUBMENU:=Utilities
  CATEGORY:=Ruijie Properties
  TITLE:=Ruijie tipc tool for est
  DEPENDS:=+libjson-c +libpthread +uci +libopenssl +rg_crypto
ifeq ($(CONFIG_PACKAGE_fredis), y)
	DEPENDS += +rg_proto +fredis
endif
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -r ./src $(PKG_BUILD_DIR)/
	$(CP) -r ./init.d $(PKG_BUILD_DIR)/
	$(CP) -r ./sbin $(PKG_BUILD_DIR)/
	$(CP) -r ./bin $(PKG_BUILD_DIR)/
	$(CP) -r ./usr $(PKG_BUILD_DIR)/
endef
TARGET_CFLAGS += -g #-DCONFIG_TIPC_CORE_DUBUG
ifeq ($(CONFIG_PACKAGE_fredis), y)
TARGET_CFLAGS += -DEST_SUPPORT_REDIS
endif
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src/ CC="$(TARGET_CC)" CROSS_COMPILE="$(TARGET_CROSS)"\
			CFLAGS="$(TARGET_CFLAGS)"
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DIR) $(1)/usr/local/schedule/1_min_crontab_task
	
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/tipc-config $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/rg_tipc_config $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/rg_tipc_server_shell $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/rg_tipc_client_shell $(1)/sbin/rg_est_wds_sync
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/rg_tipc_mac_to_nodeadd $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/init.d/rg_tipc $(1)/etc/init.d/rg_tipc
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/rg_tipc_server_ping $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/rg_tipc_client_ping $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/rg_tipc_server_upgrade $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/rg_tipc_client_upgrade $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/rg_tipc_server_download $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/rg_tipc_client_download $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/rg_tipc_ping.sh $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sbin/* $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/* $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/local/schedule/1_min_crontab_task/* $(1)/usr/local/schedule/1_min_crontab_task/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
