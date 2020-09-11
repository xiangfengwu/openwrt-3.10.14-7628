include $(TOPDIR)/rules.mk

PKG_NAME:=sshpass
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/sshpass
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=sshpass
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./sshpass/* $(PKG_BUILD_DIR)/
endef

define Package/sshpass/description
  sshpass
endef


define Package/sshpass/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sshpass $(1)/bin/
endef

$(eval $(call BuildPackage,sshpass))
