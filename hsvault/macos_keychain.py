"""Call macOS Keychain Services directly: passwords never enter process argv."""
import ctypes as c
import ctypes.util

def perform(operation, service, account, value=None):
    security = c.CDLL(ctypes.util.find_library('Security'))
    core = c.CDLL(ctypes.util.find_library('CoreFoundation'))
    pointer, count = c.c_void_p, c.c_uint32
    find = security.SecKeychainFindGenericPassword
    find.argtypes = [pointer, count, c.c_char_p, count, c.c_char_p, c.POINTER(count), c.POINTER(pointer), c.POINTER(pointer)]
    find.restype = c.c_int32
    add = security.SecKeychainAddGenericPassword
    add.argtypes = [pointer, count, c.c_char_p, count, c.c_char_p, count, pointer, c.POINTER(pointer)]
    add.restype = c.c_int32
    modify = security.SecKeychainItemModifyAttributesAndData
    modify.argtypes = [pointer, pointer, count, pointer]; modify.restype = c.c_int32
    delete = security.SecKeychainItemDelete
    delete.argtypes = [pointer]; delete.restype = c.c_int32
    free = security.SecKeychainItemFreeContent
    free.argtypes = [pointer, pointer]; free.restype = c.c_int32
    core.CFRelease.argtypes = [pointer]; core.CFRelease.restype = None
    service, account = service.encode(), account.encode()
    length, data, item = count(), pointer(), pointer()
    result = find(None, len(service), service, len(account), account,
                  c.byref(length) if operation == 'get' else None,
                  c.byref(data) if operation == 'get' else None, c.byref(item))
    try:
        if operation == 'get':
            return c.string_at(data, length.value).decode() if result == 0 else None
        if operation == 'clear': return result == 0 and delete(item) == 0
        password = value.encode()
        if result == 0: return modify(item, None, len(password), password) == 0
        if result == -25300:
            return add(None, len(service), service, len(account), account,
                       len(password), password, c.byref(item)) == 0
        return False
    finally:
        if data.value: free(None, data)
        if item.value: core.CFRelease(item)
