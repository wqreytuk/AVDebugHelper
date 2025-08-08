#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(GUIDFriendlyName, (DE1AB18A, 8A37, 43FB, B3BB, E503D293A33F),  \
        WPP_DEFINE_BIT(FOR_DEBUG) \
		WPP_DEFINE_BIT(FOR_FILTER_FILENAME) \
		WPP_DEFINE_BIT(FOR_DRIVER_STATUS)  )



#define WPP_FLAG_LEVEL_LOGGER(FLAG,LEVEL) \
           WPP_LEVEL_LOGGER(FLAG)

#define WPP_FLAG_LEVEL_ENABLED(FLAG,LEVEL) \
           (WPP_LEVEL_ENABLED(FLAG) && WPP_CONTROL(WPP_BIT_ ## FLAG).Level >= LEVEL)

// �������ﶨ���˿�����LEVEL   ��ʱ��tracelogָ����ͬ��level  ����ָ��1 ��ôleveleΪ2 �ľͲ������
// ���ǲ��ö���LEVEL��level����ddk�ж��������ֱ���þ���
 // #define WPP_DRIVER_INFO 1
 // #define WPP_FILTER_INFO 2
