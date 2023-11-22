#
# Copyright (C) 2006-2012 OpenWrt.org
# Copyright (C) 2010 Vertical Communications
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=rg-wds-networkid
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SUBMENU:=Utilities
  CATEGORY:=Ruijie Properties
  TITLE:=Ruijie wds-network-id
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./bin $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/* $(1)/usr/bin

ifeq ($(CONFIG_PACKAGE_cloud_mqlink),y)
	# 适配mqlink
	$(INSTALL_DIR) $(1)/etc/mqlink.d/syncreq
	$(INSTALL_BIN) ./etc/mqlink.d/syncreq/syncrsp.lua $(1)/etc/mqlink.d/syncreq
	$(INSTALL_DIR) $(1)/etc/mqlink.d/connect
	cd $(1)/etc/mqlink.d/connect && ln -sf /etc/mqlink.d/syncreq/syncrsp.lua syncrsp.lua
endif
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
