# Kernel module rg_qmi

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=wds_link_check
PKG_RELEASE:=1
include $(INCLUDE_DIR)/package.mk

define KernelPackage/$(PKG_NAME)
	SECTION:=Ruijie qmi
	CATEGORY:=Ruijie Properties
	SUBMENU:=Kernel modules
	TITLE:= Ruijie wds_link_check Module
	FILES:=$(PKG_BUILD_DIR)/wds_link_check.ko
	AUTOLOAD:=$(call AutoLoad,63,$(PKG_NAME))
endef
 
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./wds_link/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	 $(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		PATH="$(TARGET_PATH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
        modules
endef

$(eval $(call KernelPackage,$(PKG_NAME)))

