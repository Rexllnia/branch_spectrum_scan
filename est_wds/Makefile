#
# Copyright (C) 2006-2012 OpenWrt.org
# Copyright (C) 2010 Vertical Communications
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=rg-wds-gpio
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SUBMENU:=Utilities
  CATEGORY:=Ruijie Properties
  TITLE:=Ruijie wds-gpio
   DEPENDS:=+libuci +libpcap +libpthread +libjson-c
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -r ./src $(PKG_BUILD_DIR)/
	$(CP) -r ./etc $(PKG_BUILD_DIR)/
	$(CP) -r ./sbin $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src/ CC="$(TARGET_CC)" CROSS_COMPILE="$(TARGET_CROSS)"
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/sbin

	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/rg_wds_gpio $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/init.d/* $(1)/etc/init.d/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sbin/* $(1)/sbin
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
