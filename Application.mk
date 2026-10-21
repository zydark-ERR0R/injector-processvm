APP_ABI := arm64-v8a
APP_PLATFORM := android-28
APP_STL := c++_static
APP_OPTIM := release
APP_PIE := true
APP_CFLAGS := -O2 -DNDEBUG
APP_LDFLAGS := -llog
APP_BUILD_SCRIPT := Android.mk