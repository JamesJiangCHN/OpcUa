package pl.folkert.opcua;

import com.prosysopc.ua.ApplicationIdentity;
import com.prosysopc.ua.CertificateValidationListener;
import com.prosysopc.ua.PkiFileBasedCertificateValidator;
import com.prosysopc.ua.PkiFileBasedCertificateValidator.CertificateCheck;
import com.prosysopc.ua.PkiFileBasedCertificateValidator.ValidationResult;
import com.prosysopc.ua.SecureIdentityException;
import com.prosysopc.ua.ServiceException;
import com.prosysopc.ua.SessionActivationException;
import com.prosysopc.ua.StatusException;
import com.prosysopc.ua.UserIdentity;
import com.prosysopc.ua.client.InvalidServerEndpointException;
import com.prosysopc.ua.client.MonitoredDataItem;
import com.prosysopc.ua.client.MonitoredDataItemListener;
import com.prosysopc.ua.client.MonitoredEventItem;
import com.prosysopc.ua.client.ServerConnectionException;
import com.prosysopc.ua.client.ServerStatusListener;
import com.prosysopc.ua.client.Subscription;
import com.prosysopc.ua.client.SubscriptionAliveListener;
import com.prosysopc.ua.client.SubscriptionNotificationListener;
import com.prosysopc.ua.client.UaClient;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.EnumSet;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.opcfoundation.ua.builtintypes.DataValue;
import org.opcfoundation.ua.builtintypes.DiagnosticInfo;
import org.opcfoundation.ua.builtintypes.LocalizedText;
import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.builtintypes.StatusCode;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
import org.opcfoundation.ua.builtintypes.Variant;
import org.opcfoundation.ua.core.ApplicationDescription;
import org.opcfoundation.ua.core.ApplicationType;
import org.opcfoundation.ua.core.MonitoringMode;
import org.opcfoundation.ua.core.NotificationData;
import org.opcfoundation.ua.core.ServerState;
import org.opcfoundation.ua.core.ServerStatusDataType;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.SecurityMode;

/**
 * A sample OPC UA client, running from the console.
 */
public class SubscriptionClient {

    public SubscriptionClient() throws CertificateExpiredException, CertificateNotYetValidException, IOException, InvalidKeySpecException, SecureIdentityException, ServerConnectionException, SessionActivationException, URISyntaxException {
	PropertyConfigurator.configure(OpcUaServer.class.getResource("log.properties"));
	primaryClient = new UaClient("opc.tcp://" + Common.PRIMARY_UA_SERVER_HOST + ":" + Common.PRIMARY_UA_SERVER_PORT + "/" + Common.PRIMARY_UA_SERVER_NAME);
	secondaryClient = new UaClient("opc.tcp://" + Common.SECONDARY_UA_SERVER_HOST + ":" + Common.SECONDARY_UA_SERVER_PORT + "/" + Common.SECONDARY_UA_SERVER_NAME);

	final PkiFileBasedCertificateValidator validator = new PkiFileBasedCertificateValidator();
	primaryClient.setCertificateValidator(validator);
	secondaryClient.setCertificateValidator(validator);
	validator.setValidationListener(validationListener);

	ApplicationDescription appDescription = new ApplicationDescription();
	appDescription.setApplicationName(new LocalizedText(APP_NAME, Locale.ENGLISH));
	appDescription.setApplicationUri("urn:localhost:UA:SampleConsoleClient");
	appDescription.setProductUri("urn:prosysopc.com:UA:SampleConsoleClient");
	appDescription.setApplicationType(ApplicationType.Client);

	final ApplicationIdentity primaryIdentity = ApplicationIdentity.loadOrCreateCertificate(appDescription, "EkDan",
			    /* Private Key Password */ null,
			    /* Key File Path */ new File(validator.getBaseDir(), "private"),
			    /* Enable renewing the certificate */ true);
	final ApplicationIdentity secondaryIdentity = ApplicationIdentity.loadOrCreateCertificate(appDescription, "EkDan",
			    /* Private Key Password */ null,
			    /* Key File Path */ new File(validator.getBaseDir(), "private"),
			    /* Enable renewing the certificate */ true);

	primaryClient.setApplicationIdentity(primaryIdentity);
	primaryClient.setTimeout(30000);
	primaryClient.addServerStatusListener(serverStatusListener);
	primaryClient.setSecurityMode(securityMode);
	primaryClient.setUserIdentity(new UserIdentity());
	primaryClient.setStatusCheckInterval(Common.SERVER_STATUS_CHECK_INTERVAL);

	secondaryClient.setApplicationIdentity(secondaryIdentity);
	secondaryClient.setTimeout(30000);
	secondaryClient.setSecurityMode(securityMode);
	secondaryClient.setUserIdentity(new UserIdentity());
	secondaryClient.setStatusCheckInterval(Common.SERVER_STATUS_CHECK_INTERVAL);
    }
    private ArrayList<MonitoredDataItem> secondaryMonitoredItems = new ArrayList<>();
    private static final Logger logger = Logger.getLogger(SubscriptionClient.class.getCanonicalName());
    private static final String APP_NAME = SubscriptionClient.class.getSimpleName();
    private UaClient primaryClient;
    private UaClient secondaryClient;
    private Subscription primarySubscription = new Subscription();
    private Subscription secondarySubscription = new Subscription();
    private int sessionCount = 0;
    private boolean communicationOk = true;
    private static final UnsignedInteger attributeId = new UnsignedInteger(13);
    private SecurityMode securityMode = SecurityMode.NONE;
    private MonitoredDataItemListener dataChangeListener = new MonitoredDataItemListener() {
	@Override
	public void onDataChange(MonitoredDataItem sender, DataValue prevValue, DataValue value) {
	    //System.out.println(value.getValue() + " " + value.getSourceTimestamp().toString() + " " + value.getServerTimestamp().toString());
	}
    };
    private ServerStatusListener serverStatusListener = new ServerStatusListener() {
	@Override
	public void onShutdown(UaClient uaClient, long secondsTillShutdown, LocalizedText shutdownReason) {
	    System.out.printf("Server shutdown in %d seconds. Reason: %s\n", secondsTillShutdown, shutdownReason.getText());
	}

	@Override
	public void onStateChange(UaClient uaClient, ServerState oldState, ServerState newState) {
	    System.out.printf("ServerState changed from %s to %s\n", oldState, newState);
	    if (newState.equals(ServerState.CommunicationFault)) {
	    }
	}

	@Override
	public void onStatusChange(UaClient uaClient, ServerStatusDataType status) {
	    // Called whenever the server status changes, typically every
	    // StatusCheckInterval defined in the UaClient.
	    // println("ServerStatus: " + status);
	}
    };
    private SubscriptionAliveListener subscriptionAliveListener = new SubscriptionAliveListener() {
	@Override
	public void onAlive(Subscription s) {
//	    System.out.println("Subscription alive: ID=" + s.getSubscriptionId() + " lastAlive=" + timestampToString(s.getLastAlive()));
	}

	@Override
	public void onTimeout(Subscription s) {
//	    System.out.println("Subscription timeout: ID=" + s.getSubscriptionId() + " lastAlive=" + timestampToString(s.getLastAlive()));
	}

	private String timestampToString(Calendar lastAlive) {
	    return lastAlive == null ? "<never>" : SimpleDateFormat.getDateTimeInstance().format(lastAlive.getTime());
	}
    };
    private SubscriptionNotificationListener subscriptionListener = new SubscriptionNotificationListener() {
	private int lastValue = 0;

	@Override
	public void onDataChange(Subscription subscription, MonitoredDataItem item, DataValue value) {
	    if (!communicationOk) {
		System.out.println("Data received in " + (value.getValue().asClass(Integer[].class, new Integer[]{0})[0] - lastValue) + "ms.");
		communicationOk = true;
		getSecondaryClient().disconnect();
		System.exit(0);
	    }
	    if (item.getNodeId().toString().endsWith("IntObject" + nodeNumber)) {
		lastValue = value.getValue().asClass(Integer[].class, new Integer[]{0})[0];
//		System.out.println(lastValue);
	    }
	}

	@Override
	public void onError(Subscription subscription, Object notification, Exception exception) {
	    logger.log(Level.WARNING, exception.getLocalizedMessage());
	}

	@Override
	public void onEvent(Subscription subscription, MonitoredEventItem item, Variant[] eventFields) {
	}

	@Override
	public void onNotificationData(Subscription subscription, NotificationData notification) {
	}

        @Override
        public void onStatusChange(Subscription s, StatusCode sc, StatusCode sc1, DiagnosticInfo di) {
        }
    };
    private CertificateValidationListener validationListener = new CertificateValidationListener() {
	@Override
	public ValidationResult onValidate(Cert certificate, ApplicationDescription applicationDescription, EnumSet<CertificateCheck> passedChecks) {
	    return ValidationResult.AcceptPermanently;
	}
    };

    private void switchToSecondary(RedundancyMode redundancyMode) throws ServiceException, AssertionError, InvalidServerEndpointException, StatusException {
	System.out.println("Switching to secondary in " + redundancyMode.name() + " mode.");
	primaryClient.removeServerStatusListener(serverStatusListener);
	switch (redundancyMode) {
	    case COLD:
		secondaryClient.connect();
		for (int i = 0; i < Common.ITEMS_COUNT; i++) {
		    subscribe(secondaryClient, secondarySubscription, new NodeId(2, "IntObject" + i), Common.SAMPLING_INTERVAL);
		}
		secondarySubscription.setPublishingEnabled(true);
		break;
	    case WARM:
		for (MonitoredDataItem monitoredDataItem : secondaryMonitoredItems) {
		    monitoredDataItem.setSamplingInterval(Common.SAMPLING_INTERVAL);
		}
		secondarySubscription.setPublishingEnabled(true);
		break;
	    case HOT:
		secondarySubscription.setPublishingEnabled(true);
		break;
	    default:
		throw new AssertionError();
	}
	communicationOk = false;
    }

    public UaClient getPrimaryClient() {
	return primaryClient;
    }

    public UaClient getSecondaryClient() {
	return secondaryClient;
    }

    public void connect(UaClient client) throws ServerConnectionException {
	if (!client.isConnected()) {
	    try {
		client.setSessionName(APP_NAME + " Session" + ++sessionCount);

		long nanoTime = System.nanoTime();
		client.connect();
		nanoTime = System.nanoTime() - nanoTime;

		System.out.println("Client " + client.getSession().getName() + " connected to server within " + (nanoTime / (double) 1000000) + "ms.");

	    } catch (InvalidServerEndpointException | ServiceException e) {
		logger.log(Level.WARNING, e.getLocalizedMessage(), e);
		System.exit(-1);
	    }
	}
    }

    public MonitoredDataItem subscribe(UaClient client, Subscription subscription, NodeId nodeId, double samplingInterval) {
	MonitoredDataItem dataItem = null;
	if (attributeId != null) {
	    try {
		if (subscription == null) {
		    subscription = new Subscription();
		    subscription.addAliveListener(subscriptionAliveListener);
		    subscription.addNotificationListener(subscriptionListener);
		    subscription.setMaxKeepAliveCount(Common.KEEP_ALIVE);
		}
		if (!client.hasSubscription(subscription.getSubscriptionId())) {
		    client.addSubscription(subscription);
		}
		if (!subscription.hasItem(nodeId, attributeId)) {
		    dataItem = new MonitoredDataItem(nodeId, attributeId, MonitoringMode.Reporting);
		    dataItem.addChangeListener(dataChangeListener);
		    dataItem.setSamplingInterval(samplingInterval);
		    dataItem.setQueueSize(Common.QUEUE_SIZE);
		    subscription.addItem(dataItem);
		}
	    } catch (ServiceException | StatusException e) {
		logger.log(Level.WARNING, e.getLocalizedMessage(), e);
	    }
	}
	return dataItem;
    }

    public Subscription getPrimarySubscription() {
	return primarySubscription;
    }

    public Subscription getSecondarySubscription() {
	return secondarySubscription;
    }

    public SubscriptionAliveListener getSubscriptionAliveListener() {
	return subscriptionAliveListener;
    }

    public SubscriptionNotificationListener getSubscriptionListener() {
	return subscriptionListener;
    }

    public ArrayList<MonitoredDataItem> getSecondaryMonitoredItems() {
	return secondaryMonitoredItems;
    }
    static long idleTime = 0;
    static int nodeNumber = 0;
    static int reconnectionInterval = 10000;

    public static void main(String[] args) throws Exception {


	if (args.length == 10) {
	    switch (args[0].toLowerCase()) {
	    	case "cold":
		    Common.REDUNDANCY_MODE = RedundancyMode.COLD;
		    break;
	    	case "warm":
		    Common.REDUNDANCY_MODE = RedundancyMode.WARM;
		    break;
	    	case "hot":
		    Common.REDUNDANCY_MODE = RedundancyMode.HOT;
		    break;
	    }

	    Common.PUBLISHING_INTERVAL = Integer.parseInt(args[1]);
	    Common.QUEUE_SIZE = Integer.parseInt(args[2]);
	    Common.KEEP_ALIVE = Integer.parseInt(args[3]);
	    Common.PRIMARY_UA_SERVER_HOST = args[4];
	    Common.SECONDARY_UA_SERVER_HOST = args[5];
	    idleTime = Long.parseLong(args[6]);
	    Common.ITEMS_COUNT = Integer.parseInt(args[7]);
	    nodeNumber = Integer.parseInt(args[8]);
	    reconnectionInterval = Integer.parseInt(args[9]);

	} else {
	    System.out.println("Parameters: ");
	    System.out.println("\t1. Redundancy mode (cold, warm or hot)");
	    System.out.println("\t2. Subscription interval");
	    System.out.println("\t3. Queue size");
	    System.out.println("\t4. Keep alive");
	    System.out.println("\t5. Primary server address");
	    System.out.println("\t6. Secondary server address");
	    System.out.println("\t7. Idle time between disconnection and failover actions");
	    System.out.println("\t8. Item count");
	    System.out.println("\t9. Node number");
	    System.out.println("\t10.Reconnection interval");
	    System.exit(-1);
	}

	SubscriptionClient subscriptionClient = new SubscriptionClient();

	subscriptionClient.connect(subscriptionClient.getPrimaryClient());

	long nanoTime = System.nanoTime();
	subscriptionClient.getPrimarySubscription().addAliveListener(subscriptionClient.getSubscriptionAliveListener());
	subscriptionClient.getPrimarySubscription().addNotificationListener(subscriptionClient.getSubscriptionListener());

	for (int i = 0; i < Common.ITEMS_COUNT; i++) {
	    subscriptionClient.subscribe(subscriptionClient.getPrimaryClient(), subscriptionClient.getPrimarySubscription(), new NodeId(2, "IntObject" + i), Common.SAMPLING_INTERVAL);
	}

	nanoTime = System.nanoTime() - nanoTime;
	System.out.println("Subscription with " + Common.ITEMS_COUNT + " monitored data items created within " + (nanoTime / (double) 1000000) + "ms.");

	subscriptionClient.getPrimarySubscription().setPublishingEnabled(true);

	subscriptionClient.getPrimarySubscription().setPublishingInterval(Common.PUBLISHING_INTERVAL);
	subscriptionClient.getSecondarySubscription().setPublishingInterval(Common.PUBLISHING_INTERVAL);

	subscriptionClient.getSecondarySubscription().addAliveListener(subscriptionClient.getSubscriptionAliveListener());
	subscriptionClient.getSecondarySubscription().addNotificationListener(subscriptionClient.getSubscriptionListener());

	switch (Common.REDUNDANCY_MODE) {
	    case WARM:
		System.out.println("*** WARM MODE ACTIVE ***");
		subscriptionClient.getSecondaryClient().connect();
		for (int i = 0; i < Common.ITEMS_COUNT; i++) {
		    subscriptionClient.getSecondaryMonitoredItems().add(subscriptionClient.subscribe(subscriptionClient.getSecondaryClient(), subscriptionClient.getSecondarySubscription(), new NodeId(2, "IntObject" + i), -1));
		}
		break;
	    case HOT:
		System.out.println("*** HOT MODE ACTIVE ***");
		subscriptionClient.getSecondaryClient().connect();
		for (int i = 0; i < Common.ITEMS_COUNT; i++) {
		    subscriptionClient.getSecondaryMonitoredItems().add(subscriptionClient.subscribe(subscriptionClient.getSecondaryClient(), subscriptionClient.getSecondarySubscription(), new NodeId(2, "IntObject" + i), Common.SAMPLING_INTERVAL));
		}
		break;
	    default:
		System.out.println("*** COLD MODE ACTIVE ***");
		break;
	}

	subscriptionClient.getSecondarySubscription().setPublishingInterval(Common.SAMPLING_INTERVAL);
	subscriptionClient.getSecondarySubscription().setPublishingEnabled(false);

	try {
	    TimeUnit.MILLISECONDS.sleep(reconnectionInterval);
	} catch (InterruptedException e) {
	    System.out.println(e.getLocalizedMessage());
	}

	subscriptionClient.getPrimaryClient().disconnect();

	try {
	    TimeUnit.MILLISECONDS.sleep(idleTime);
	} catch (InterruptedException e) {
	    System.out.println(e.getLocalizedMessage());
	}

	try {
	    long time = System.currentTimeMillis();
	    subscriptionClient.switchToSecondary(Common.REDUNDANCY_MODE);
	    System.out.println("Switched in " + (System.currentTimeMillis() - time) + "ms.");
	} catch (AssertionError | InvalidServerEndpointException | ServiceException | StatusException ex) {
	    System.err.println(ex);
	}

    }
}
