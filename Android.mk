LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := injector
LOCAL_SRC_FILES := src/main.cpp
LOCAL_CPPFLAGS  := -std=c++17 -O2 -fPIE -fvisibility=hidden
LOCAL_LDLIBS    := -llog -ldl -landroid
LOCAL_CFLAGS    := -fPIE -pie
LOCAL_LDFLAGS   := -fPIE -pie
include $(BUILD_EXECUTABLE)