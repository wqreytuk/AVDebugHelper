#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(GUIDFriendlyName, (DE1AB18A, 8A37, 43FB, B3BB, E503D293A33F),  \
        WPP_DEFINE_BIT(FOR_DEBUG) \
		WPP_DEFINE_BIT(FOR_FILTER_FILENAME) \
		WPP_DEFINE_BIT(FOR_DRIVER_STATUS)  )



#define WPP_FLAG_LEVEL_LOGGER(FLAG,LEVEL) \
           WPP_LEVEL_LOGGER(FLAG)

#define WPP_FLAG_LEVEL_ENABLED(FLAG,LEVEL) \
           (WPP_LEVEL_ENABLED(FLAG) && WPP_CONTROL(WPP_BIT_ ## FLAG).Level >= LEVEL)

// 我在这里定义了可两个LEVEL   到时候tracelog指定不同的level  比如指定1 那么levele为2 的就不会输出
// 我们不用定义LEVEL，level是在ddk中定义的我们直接用就行
 // #define WPP_DRIVER_INFO 1
 // #define WPP_FILTER_INFO 2
