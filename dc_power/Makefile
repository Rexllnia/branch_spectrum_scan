
include $(TOPDIR)/rules.mk

PKG_NAME:=rg-dc-power
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SUBMENU:=Utilities
  CATEGORY:=Ruijie Properties
  TITLE:=Ruijie DC Power
endef

define Build/Prepare
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/local/lua/dev_config
	$(INSTALL_DIR) $(1)/usr/local/lua/dev_sta
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./etc/init.d/* $(1)/etc/init.d/
	$(INSTALL_BIN) ./dev_sta/* $(1)/usr/local/lua/dev_sta/
	$(INSTALL_BIN) ./dev_config/* $(1)/usr/local/lua/dev_config/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
