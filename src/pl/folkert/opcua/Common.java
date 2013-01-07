package pl.folkert.opcua;

public class Common {

    public static RedundancyMode REDUNDANCY_MODE = RedundancyMode.COLD;
    public static int ITEMS_COUNT = 10;
    public static int SAMPLING_INTERVAL = 200;
    public static int PUBLISHING_INTERVAL = 10000;
    public static int SYNCHRO_INTERVAL = 1000;
    public static int DATA_ARRAY_SIZE = 1;
    public static int QUEUE_SIZE  = 1;
    public static int KEEP_ALIVE  = 1;
    public static int PRIMARY_UA_SERVER_PORT = 4080;
    public static int SECONDARY_UA_SERVER_PORT = 4080;
    public static int SYNCHRO_SERVER_PORT = 8888;
    public static int SOURCE_SERVER_PORT = 1234;
    public static int SERVER_STATUS_CHECK_INTERVAL = 1000;
    public static String PRIMARY_UA_SERVER_HOST = "kfolkert_laptop";
//    public static String PRIMARY_UA_SERVER_HOST = "158.37.15.160";
    public static String SECONDARY_UA_SERVER_HOST = "kfolkert_laptop";
//    public static String SECONDARY_UA_SERVER_HOST = "158.37.15.160";
    public static String SYNCHRO_SERVER_HOST = "kfolkert_laptop";
    public static String SOURCE_SERVER_HOST = "kfolkert_laptop";
    public static String PRIMARY_UA_SERVER_NAME = "SubscriptionServer";
    public static String SECONDARY_UA_SERVER_NAME = "SubscriptionServer";
    public static String PRIMARY_UA_SERVER_URI = "opc.tcp://" + PRIMARY_UA_SERVER_HOST + ":" + PRIMARY_UA_SERVER_PORT + "/" + PRIMARY_UA_SERVER_NAME;
    public static String SECONDARY_UA_SERVER_URI = "opc.tcp://" + SECONDARY_UA_SERVER_HOST + ":" + SECONDARY_UA_SERVER_PORT + "/" + SECONDARY_UA_SERVER_NAME;
}