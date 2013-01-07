package pl.folkert.opcua;

import com.prosysopc.ua.ApplicationIdentity;
import com.prosysopc.ua.CertificateValidationListener;
import com.prosysopc.ua.PkiFileBasedCertificateValidator;
import com.prosysopc.ua.PkiFileBasedCertificateValidator.CertificateCheck;
import com.prosysopc.ua.PkiFileBasedCertificateValidator.ValidationResult;
import com.prosysopc.ua.SecureIdentityException;
import com.prosysopc.ua.StatusException;
import com.prosysopc.ua.UserIdentity;
import com.prosysopc.ua.WriteAccess;
import com.prosysopc.ua.nodes.DataChangeListener;
import com.prosysopc.ua.nodes.UaMethod;
import com.prosysopc.ua.nodes.UaNode;
import com.prosysopc.ua.nodes.UaNodeFactoryException;
import com.prosysopc.ua.nodes.UaReference;
import com.prosysopc.ua.nodes.UaReferenceType;
import com.prosysopc.ua.nodes.UaVariable;
import com.prosysopc.ua.server.EventManagerListener;
import com.prosysopc.ua.server.IoManagerListener;
import com.prosysopc.ua.server.MonitoredDataItem;
import com.prosysopc.ua.server.MonitoredEventItem;
import com.prosysopc.ua.server.NodeManagerListener;
import com.prosysopc.ua.server.NodeManagerUaNode;
import com.prosysopc.ua.server.ServiceContext;
import com.prosysopc.ua.server.Session;
import com.prosysopc.ua.server.Subscription;
import com.prosysopc.ua.server.UaServer;
import com.prosysopc.ua.server.UaServerException;
import com.prosysopc.ua.server.UserValidator;
import com.prosysopc.ua.server.nodes.PlainProperty;
import com.prosysopc.ua.server.nodes.UaVariableNode;
import com.prosysopc.ua.server.nodes.opcua.AcknowledgeableConditionType;
import com.prosysopc.ua.server.nodes.opcua.AlarmConditionType;
import com.prosysopc.ua.server.nodes.opcua.BaseEventType;
import com.prosysopc.ua.server.nodes.opcua.BuildInfoType;
import com.prosysopc.ua.server.nodes.opcua.ConditionType;
import com.prosysopc.ua.server.nodes.opcua.FolderType;
import com.prosysopc.ua.server.nodes.opcua.ShelvedStateMachineType;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.opcfoundation.ua.builtintypes.DataValue;
import org.opcfoundation.ua.builtintypes.DateTime;
import org.opcfoundation.ua.builtintypes.ExpandedNodeId;
import org.opcfoundation.ua.builtintypes.LocalizedText;
import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.builtintypes.QualifiedName;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
import org.opcfoundation.ua.builtintypes.Variant;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.AccessLevel;
import org.opcfoundation.ua.core.AggregateFilterResult;
import org.opcfoundation.ua.core.ApplicationDescription;
import org.opcfoundation.ua.core.EventFilter;
import org.opcfoundation.ua.core.EventFilterResult;
import org.opcfoundation.ua.core.Identifiers;
import org.opcfoundation.ua.core.MonitoringFilter;
import org.opcfoundation.ua.core.MonitoringParameters;
import org.opcfoundation.ua.core.NodeAttributes;
import org.opcfoundation.ua.core.NodeClass;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.core.TimestampsToReturn;
import org.opcfoundation.ua.core.UserTokenPolicy;
import org.opcfoundation.ua.core.UserTokenType;
import org.opcfoundation.ua.core.ViewDescription;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.SecurityMode;
import org.opcfoundation.ua.utils.NumericRange;

/**
 * A sample OPC UA server application.
 */
public class SampleConsoleServer {

    enum Action {

        ADD_NODE("add a new node"), CLOSE("close the server"), DELETE_NODE(
        "delete a node"), ENABLE_DIAGNOSTICS(
        "enable/disable server diagnostics");
        static Map<String, Action> actionMap = new HashMap<>();

        static {
            actionMap.put("a", ADD_NODE);
            actionMap.put("d", DELETE_NODE);
            actionMap.put("e", ENABLE_DIAGNOSTICS);
            actionMap.put("x", CLOSE);
        }

        public static Action parseAction(String s) {
            return actionMap.get(s);
        }
        private final String description;

        Action(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    /**
     * A sample class for keeping a history of a variable node.
     */
    static class ValueHistory {

        private int capacity = 10000;
        private final DataChangeListener listener = new DataChangeListener() {
            @Override
            public void onDataChange(UaNode uaNode, DataValue prevValue,
                    DataValue value) {
                values.add(value);
                while (values.size() > capacity) {
                    values.remove(0);
                }
            }
        };
        private final List<DataValue> values = new CopyOnWriteArrayList<>();
        private final UaVariable variable;

        public ValueHistory(UaVariableNode variable) {
            super();
            this.variable = variable;
            variable.addDataChangeListener(listener);
        }

        public int getCapacity() {
            return capacity;
        }

        /**
         * Get the values from the history that are between startTime and
         * endTime.
         *
         * @param startTime
         * @param endTime
         * @param returnBounds
         * @param maxValues
         * @return
         */
        public DataValue[] getHistory(DateTime startTime, DateTime endTime,
                int maxValues, boolean returnBounds) {
            List<DataValue> history = new ArrayList<>();
            for (DataValue value : values) {
                DateTime t = value.getSourceTimestamp();
                if (t == null) {
                    t = value.getServerTimestamp();
                }
                final int compareToEnd = t.compareTo(endTime);
                if ((compareToEnd > 0)
                        || (!returnBounds && (compareToEnd == 0))) {
                    break;
                } else {
                    final int compareToStart = t.compareTo(startTime);
                    if ((compareToStart > 0)
                            || (returnBounds && (compareToStart == 0))) {
                        history.add(value);
                        if (history.size() == maxValues) {
                            break;
                        }
                    }
                }
            }
            return history.toArray(new DataValue[history.size()]);
        }

        /**
         * @return the variable
         */
        public UaVariable getVariable() {
            return variable;
        }

        /**
         * @param capacity the capacity to set
         */
        public void setCapacity(int capacity) {
            if (capacity < 0) {
                throw new IllegalArgumentException(
                        "capacity must be a positive value");
            }
            this.capacity = capacity;
        }
    }
    private static final String APP_NAME = "SampleConsoleServer";
    private static int eventId = 0;
    private static Logger logger = Logger.getLogger(SampleConsoleServer.class);
    private static BigNodeManager myBigNodeManager;
    private static EventManagerListener myEventManagerListener = new EventManagerListener() {
        @Override
        public boolean onAcknowledge(ServiceContext serviceContext,
                AcknowledgeableConditionType condition, byte[] eventId,
                LocalizedText comment) throws StatusException {
            // Handle acknowledge request to a condition event
            println("Acknowledge: Condition=" + condition + "; EventId="
                    + eventIdToString(eventId) + "; Comment=" + comment);
            // If the acknowledged event is no longer active, return an error
            if (!Arrays.equals(eventId, condition.getEventId())) {
                throw new StatusException(StatusCodes.Bad_EventIdUnknown);
            }
            if (condition.isAcked()) {
                throw new StatusException(
                        StatusCodes.Bad_ConditionBranchAlreadyAcked);
            }
            // If the condition is no longer active, set retain to false, i.e.
            // remove it from the visible alarms
            if (!(condition instanceof AlarmConditionType)
                    || !((AlarmConditionType) condition).isActive()) {
                condition.setRetain(false);
            }

            final DateTime now = DateTime.currentTime();
            condition.setAcked(true, now);
            final byte[] userEventId = getNextUserEventId();
            // addComment triggers a new event
            condition.addComment(eventId, comment, now, userEventId);
            return true; // Handled here
            // NOTE: If you do not handle acknowledge here, and return false,
            // the EventManager (or MethodManager) will call
            // condition.acknowledge, which performs the same actions as this
            // handler, except for setting Retain
        }

        @Override
        public boolean onAddComment(ServiceContext serviceContext,
                ConditionType condition, byte[] eventId, LocalizedText comment)
                throws StatusException {
            // Handle add command request to a condition event
            println("AddComment: Condition=" + condition + "; Event="
                    + eventIdToString(eventId) + "; Comment=" + comment);
            // Only the current eventId can get comments
            if (!Arrays.equals(eventId, condition.getEventId())) {
                throw new StatusException(StatusCodes.Bad_EventIdUnknown);
            }
            // triggers a new event
            final byte[] userEventId = getNextUserEventId();
            condition.addComment(eventId, comment, DateTime.currentTime(),
                    userEventId);
            return true; // Handled here
            // NOTE: If you do not handle addComment here, and return false,
            // the EventManager (or MethodManager) will call
            // condition.addComment automatically
        }

        @Override
        public void onAfterCreateMonitoredEventItem(
                ServiceContext serviceContext, Subscription subscription,
                MonitoredEventItem item) {
            //
        }

        @Override
        public void onAfterDeleteMonitoredEventItem(
                ServiceContext serviceContext, Subscription subscription,
                MonitoredEventItem item) {
            //
        }

        @Override
        public void onAfterModifyMonitoredEventItem(
                ServiceContext serviceContext, Subscription subscription,
                MonitoredEventItem item) {
            //
        }

        @Override
        public void onConditionRefresh(ServiceContext serviceContext,
                Subscription subscription) throws StatusException {
            //
        }

        @Override
        public boolean onConfirm(ServiceContext serviceContext,
                AcknowledgeableConditionType condition, byte[] eventId,
                LocalizedText comment) throws StatusException {
            // Handle confirm request to a condition event
            println("Confirm: Condition=" + condition + "; EventId="
                    + eventIdToString(eventId) + "; Comment=" + comment);
            // If the confirmed event is no longer active, return an error
            if (!Arrays.equals(eventId, condition.getEventId())) {
                throw new StatusException(StatusCodes.Bad_EventIdUnknown);
            }
            if (condition.isConfirmed()) {
                throw new StatusException(
                        StatusCodes.Bad_ConditionBranchAlreadyConfirmed);
            }
            if (!condition.isAcked()) {
                throw new StatusException(
                        "Condition can only be confirmed when it is acknowledged.",
                        StatusCodes.Bad_InvalidState);
            }
            final DateTime now = DateTime.currentTime();
            condition.setConfirmed(true, now);
            final byte[] userEventId = getNextUserEventId();
            // addComment triggers a new event
            condition.addComment(eventId, comment, now, userEventId);
            return true; // Handled here
            // NOTE: If you do not handle Confirm here, and return false,
            // the EventManager (or MethodManager) will call
            // condition.confirm, which performs the same actions as this
            // handler
        }

        @Override
        public void onCreateMonitoredEventItem(ServiceContext serviceContext,
                NodeId nodeId, EventFilter eventFilter,
                EventFilterResult filterResult) throws StatusException {
            // Item created
        }

        @Override
        public void onDeleteMonitoredEventItem(ServiceContext serviceContext,
                Subscription subscription, MonitoredEventItem monitoredItem) {
            // Stop monitoring the item?
        }

        @Override
        public boolean onDisable(ServiceContext serviceContext,
                ConditionType condition) throws StatusException {
            // Handle disable request to a condition
            println("Disable: Condition=" + condition);
            if (condition.isEnabled()) {
                DateTime now = DateTime.currentTime();
                // Setting enabled to false, also sets retain to false
                condition.setEnabled(false, now);
                // notify the clients of the change
                condition.triggerEvent(now, null, getNextUserEventId());
            }
            return true; // Handled here
            // NOTE: If you do not handle disable here, and return false,
            // the EventManager (or MethodManager) will request the
            // condition to handle the call, and it will unset the enabled
            // state, and triggers a new notification event, as here
        }

        @Override
        public boolean onEnable(ServiceContext serviceContext,
                ConditionType condition) throws StatusException {
            // Handle enable request to a condition
            println("Enable: Condition=" + condition);
            if (!condition.isEnabled()) {
                DateTime now = DateTime.currentTime();
                condition.setEnabled(true, now);
                // You should evaluate the condition now, set Retain to true,
                // if necessary and in that case also call triggerEvent
                // condition.setRetain(true);
                // condition.triggerEvent(now, null, getNextUserEventId());
            }
            return true; // Handled here
            // NOTE: If you do not handle enable here, and return false,
            // the EventManager (or MethodManager) will request the
            // condition to handle the call, and it will set the enabled
            // state.

            // You should however set the status of the condition yourself
            // and trigger a new event if necessary
        }

        @Override
        public void onModifyMonitoredEventItem(ServiceContext serviceContext,
                Subscription subscription, MonitoredEventItem monitoredItem,
                EventFilter eventFilter, EventFilterResult filterResult)
                throws StatusException {
            // Modify event monitoring, when the client modifies a monitored
            // item
        }

        @Override
        public boolean onOneshotShelve(ServiceContext serviceContext,
                AlarmConditionType condition,
                ShelvedStateMachineType stateMachine) throws StatusException {
            return false;
        }

        @Override
        public boolean onTimedShelve(ServiceContext serviceContext,
                AlarmConditionType condition,
                ShelvedStateMachineType stateMachine, double shelvingTime)
                throws StatusException {
            return false;
        }

        @Override
        public boolean onUnshelve(ServiceContext serviceContext,
                AlarmConditionType condition,
                ShelvedStateMachineType stateMachine) throws StatusException {
            return false;
        }

        private String eventIdToString(byte[] eventId) {
            return eventId == null ? "(null)" : Arrays.toString(eventId);
        }
    };
    private static IoManagerListener myIoManagerListener = new IoManagerListener() {
        @Override
        public EnumSet<AccessLevel> onGetUserAccessLevel(
                ServiceContext serviceContext, NodeId nodeId, UaVariable node) {
            // The AccessLevel defines the accessibility of the Variable.Value
            // attribute
            return EnumSet.of(AccessLevel.CurrentRead,
                    AccessLevel.CurrentWrite, AccessLevel.HistoryRead);
        }

        @Override
        public boolean onGetUserExecutable(ServiceContext serviceContext,
                NodeId nodeId, UaMethod node) {
            // Enable execution of all methods that are allowed by default
            return true;
        }

        @Override
        public EnumSet<WriteAccess> onGetUserWriteMask(
                ServiceContext serviceContext, NodeId nodeId, UaNode node) {
            // Enable writing to everything that is allowed by default
            // The WriteMask defines the writable attributes, except for Value,
            // which is controlled by UserAccessLevel (above)

            // The following would deny write access for anonymous users:
            // if
            // (serviceContext.getSession().getUserIdentity().getType().equals(
            // UserTokenType.Anonymous))
            // return EnumSet.noneOf(WriteAccess.class);

            return EnumSet.allOf(WriteAccess.class);
        }

        @Override
        public void onReadNonValue(ServiceContext serviceContext,
                NodeId nodeId, UaNode node, UnsignedInteger attributeId,
                DataValue dataValue) throws StatusException {
            // OK
        }

        @Override
        public void onReadValue(ServiceContext serviceContext, NodeId nodeId,
                UaVariable node, NumericRange indexRange,
                TimestampsToReturn timestampsToReturn, DateTime minTimestamp,
                DataValue dataValue) throws StatusException {
            // OK
        }

        @Override
        public boolean onWriteNonValue(ServiceContext serviceContext,
                NodeId nodeId, UaNode node, UnsignedInteger attributeId,
                DataValue dataValue) throws StatusException {
            return false;
        }

        @Override
        public boolean onWriteValue(ServiceContext serviceContext,
                NodeId nodeId, UaVariable node, NumericRange indexRange,
                DataValue dataValue) throws StatusException {
            return false;
        }
    };
    private static NodeManagerUaNode myNodeManager;
    private static NodeManagerListener myNodeManagerListener = new NodeManagerListener() {
        @Override
        public void onAddNode(ServiceContext serviceContext,
                NodeId parentNodeId, UaNode parent, NodeId nodeId, UaNode node,
                NodeClass nodeClass, QualifiedName browseName,
                NodeAttributes attributes, UaReferenceType referenceType,
                ExpandedNodeId typeDefinitionId, UaNode typeDefinition)
                throws StatusException {
            // Notification of a node addition request
            checkUserIdentity(serviceContext);
        }

        @Override
        public void onAddReference(ServiceContext serviceContext,
                NodeId sourceNodeId, UaNode sourceNode,
                ExpandedNodeId targetNodeId, UaNode targetNode,
                NodeId referenceTypeId, UaReferenceType referenceType,
                boolean isForward) throws StatusException {
            // Notification of a reference addition request
            checkUserIdentity(serviceContext);
        }

        @Override
        public void onAfterCreateMonitoredDataItem(
                ServiceContext serviceContext, Subscription subscription,
                MonitoredDataItem item) {
            //
        }

        @Override
        public void onAfterDeleteMonitoredDataItem(
                ServiceContext serviceContext, Subscription subscription,
                MonitoredDataItem item) {
            //
        }

        @Override
        public void onAfterModifyMonitoredDataItem(
                ServiceContext serviceContext, Subscription subscription,
                MonitoredDataItem item) {
            //
        }

        @Override
        public boolean onBrowseNode(ServiceContext serviceContext,
                ViewDescription view, NodeId nodeId, UaNode node,
                UaReference reference) {
            // Perform custom filtering, for example based on the user
            // doing the browse
            // Default is to return all references for everyone
            return true;
        }

        @Override
        public void onCreateMonitoredDataItem(ServiceContext serviceContext,
                Subscription subscription, UaNode node,
                UnsignedInteger attributeId, String indexRange,
                MonitoringParameters params, MonitoringFilter filter,
                AggregateFilterResult filterResult) throws StatusException {
            // Notification of a monitored item creation request
            // You may, for example start to monitor the node from a physical
            // device, only once you get a request for it from a client
        }

        @Override
        public void onDeleteMonitoredDataItem(ServiceContext serviceContext,
                Subscription subscription, MonitoredDataItem monitoredItem) {
            // Notification of a monitored item delete request
        }

        @Override
        public void onDeleteNode(ServiceContext serviceContext, NodeId nodeId,
                UaNode node, boolean deleteTargetReferences)
                throws StatusException {
            // Notification of a node deletion request
            checkUserIdentity(serviceContext);
        }

        @Override
        public void onDeleteReference(ServiceContext serviceContext,
                UaNode sourceNode, ExpandedNodeId targetNodeId,
                UaReferenceType referenceType, boolean isForward,
                boolean deleteBidirectional) throws StatusException {
            // Notification of a reference deletion request
            checkUserIdentity(serviceContext);
        }

        @Override
        public void onModifyMonitoredDataItem(ServiceContext serviceContext,
                Subscription subscription, MonitoredDataItem item, UaNode node,
                MonitoringParameters params, MonitoringFilter filter,
                AggregateFilterResult filterResult) {
            // Notification of a monitored item modification request
        }

        private void checkUserIdentity(ServiceContext serviceContext)
                throws StatusException {
            // Do not allow for anonymous users
            if (serviceContext.getSession().getUserIdentity().getType()
                    .equals(UserTokenType.Anonymous)) {
                throw new StatusException(StatusCodes.Bad_UserAccessDenied);
            }
        }
    };
    private static FolderType myObjectsFolder;
    private static UaServer server;
    private final static Runnable simulationTask = new Runnable() {
        double dx = 1;

        @Override
        public void run() {
            if (server.isRunning()) {
                myBigNodeManager.setValues(System.currentTimeMillis() / 1000d);
            }
        }
    };
    private final static ScheduledExecutorService simulator = Executors
            .newScheduledThreadPool(10);
    private static boolean stackTraceOnException = true;
    private static UserValidator userValidator = new UserValidator() {
        @Override
        public boolean onValidate(Session session, UserIdentity userIdentity)
                throws StatusException {
            // Return true, if the user is allowed access to the server
            // Note that the UserIdentity can be of different actual types,
            // depending on the selected authentication mode (by the client).
            println("onValidate: userIdentity=" + userIdentity);
            if (userIdentity.getType().equals(UserTokenType.UserName)) {
                if (userIdentity.getName().equals("opcua")
                        && userIdentity.getPassword().equals("opcua")) {
                    return true;
                } else {
                    return false;
                }
            }
            if (userIdentity.getType().equals(UserTokenType.Certificate)) // Implement your strategy here, for example using the
            // PkiFileBasedCertificateValidator
            {
                return true;
            }
            return true;
        }
    };
    private static CertificateValidationListener validationListener = new CertificateValidationListener() {
        @Override
        public ValidationResult onValidate(Cert certificate,
                ApplicationDescription applicationDescription,
                EnumSet<CertificateCheck> passedChecks) {
            // Do not mind about URI...
            if (passedChecks.containsAll(EnumSet.of(CertificateCheck.Trusted,
                    CertificateCheck.Validity, CertificateCheck.Signature))) {
                if (!passedChecks.contains(CertificateCheck.Uri)) {
                    try {
                        println("Client's ApplicationURI ("
                                + applicationDescription.getApplicationUri()
                                + ") does not match the one in certificate: "
                                + PkiFileBasedCertificateValidator
                                .getApplicationUriOfCertificate(certificate));
                    } catch (CertificateParsingException e) {
                        throw new RuntimeException(e);
                    }
                }
                return ValidationResult.AcceptPermanently;
            }
            return ValidationResult.Reject;
        }
    };
    protected static Variant[] eventFieldValues;
    protected static Object eventSender;

    /**
     * @param args command line arguments for the application
     * @throws StatusException if the server address space creation fails
     * @throws CertificateExpiredException if the application certificate has
     * expired (should not happen, since we enable renewing it)
     * @throws CertificateNotYetValidException if the application certificate is
     * not yet valid (should not happen, since we are creating it ourselves)
     * @throws UaServerException if the server initialization parameters are
     * invalid
     */
    public static void main(String[] args) throws IOException,
            InvalidKeySpecException, SecureIdentityException,
            URISyntaxException, ServiceResultException, StatusException,
            CertificateNotYetValidException, CertificateExpiredException,
            UaServerException {
        PropertyConfigurator.configure(SampleConsoleServer.class
                .getResource("log.properties"));

        // *** Create the server
        server = new UaServer();

        // Use PKI files to keep track of the trusted and rejected client
        // certificates...
        final PkiFileBasedCertificateValidator validator = new PkiFileBasedCertificateValidator();
        server.setCertificateValidator(validator);
        validator.setValidationListener(validationListener);

        // *** Application Identity
        ApplicationDescription appDescription = new ApplicationDescription();
        appDescription.setApplicationName(new LocalizedText(APP_NAME,
                Locale.ENGLISH));
        // 'localhost' (all lower case) in the URI is converted to the actual
        // host name of the computer in which the application is run
        appDescription
                .setApplicationUri("urn:localhost:UA:SampleConsoleServer");
        appDescription
                .setProductUri("urn:prosysopc.com:UA:SampleConsoleServer");

        // Define the Server application identity, including the security
        // certificate.
        final ApplicationIdentity identity = ApplicationIdentity
                .loadOrCreateCertificate(appDescription, "Sample Organisation",
                /* Private Key Password */ "opcua",
                /* Key File Path */ new File(validator.getBaseDir(), "private"),
                /* Enable renewing the certificate */ true);

        server.setApplicationIdentity(identity);

        // *** Server Endpoints
        // the port for the binary protocol
        server.setPort(52520);
        // add 'localhost' to the endpoint list
        server.setUseLocalhost(true);

        // optional server name part of the URI
        server.setServerName("OPCUA/SampleConsoleServer");
        // Add the IP address(es) of the server host to the endpoints
        server.setUseAllIpAddresses(true);

        // *** Security settings
        // Define the security modes to support - ALL is the default
        server.setSecurityModes(SecurityMode.ALL);

        // Define the supported user Token policies
        server.addUserTokenPolicy(UserTokenPolicy.ANONYMOUS);
        server.addUserTokenPolicy(UserTokenPolicy.SECURE_USERNAME_PASSWORD);
        server.addUserTokenPolicy(UserTokenPolicy.SECURE_CERTIFICATE);
        // Define a validator for checking the user accounts
        server.setUserValidator(userValidator);

        // Register on the local discovery server (if present)
        server.setDiscoveryServerUrl("opc.tcp://localhost:4840");

        // *** Initialization and Start Up
        // Initialize the server, before making your own additions
        server.init();

        initBuildInfo();

        // Create the address space
        createAddressSpace();

        // Start the server, when you have finished your own initializations
        // This will allow connections from the clients
        server.start();
        startSimulation();

        // *** Main Menu Loop
        mainMenu();

        // *** End
        stopSimulation();
        // Notify the clients about a shutdown, with a 5 second delay
        println("Shutting down...");
        server.shutdown(5, new LocalizedText("Closed by user", Locale.ENGLISH));
        println("Closed.");
    }

    private static void addNode(String name) {
        // Initialize NodeVersion property, to enable ModelChangeEvents
        myObjectsFolder.initNodeVersion();

        server.getNodeManagerRoot().beginModelChange();
        try {
            NodeId nodeId = new NodeId(myNodeManager.getNamespaceIndex(),
                    UUID.randomUUID());

            UaNode node = myNodeManager.getNodeFactory().createNode(
                    NodeClass.Variable, nodeId, name, Locale.ENGLISH,
                    Identifiers.PropertyType);
            myObjectsFolder.addComponent(node);
        } catch (UaNodeFactoryException | IllegalArgumentException e) {
            logger.error(e);
        } finally {
            server.getNodeManagerRoot().endModelChange();
        }
    }

    /**
     * Create a sample address space with a new folder, a device object, a level
     * variable, and an alarm condition. <p> The method demonstrates the basic
     * means to create the nodes and references into the address space. <p>
     * Simulation of the level measurement is defined in
     * {@link #startSimulation()}
     *
     * @throws StatusException if the referred type nodes are not found from the
     * address space
     *
     */
    private static void createAddressSpace() throws StatusException {
        // My Node Manager
        myNodeManager = new NodeManagerUaNode(server,
                "http://www.prosysopc.com/OPCUA/SampleAddressSpace");

        myNodeManager.addListener(myNodeManagerListener);

        // My Event Manager Listener
        myNodeManager.getEventManager().setListener(myEventManagerListener);

        // My I/O Manager Listener
        myNodeManager.getIoManager().setListener(myIoManagerListener);
        
        createBigNodeManager();

        logger.info("Address space created.");
    }

    /**
     * Create a sample node manager, which does not use UaNode objects. These
     * are suitable for managing big address spaces for data that is in practice
     * available from another existing subsystem.
     */
    private static void createBigNodeManager() {
        myBigNodeManager = new BigNodeManager(server,
                "http://www.prosysopc.com/OPCUA/SampleBigAddressSpace", 1000);
    }

    /**
     * @param nodeName
     * @throws StatusException
     *
     */
    private static void deleteNode(QualifiedName nodeName)
            throws StatusException {
        UaNode node = myObjectsFolder.getComponent(nodeName);
        if (node != null) {
            server.getNodeManagerRoot().beginModelChange();
            try {
                myNodeManager.deleteNode(node, true, true);
            } finally {
                server.getNodeManagerRoot().endModelChange();
            }
        } else {
            println("MyObjects does not contain a component with name "
                    + nodeName);
        }
    }

    /**
     * @return @throws RuntimeException
     */
    private static byte[] getNextUserEventId() throws RuntimeException {
        return BaseEventType.createEventId(eventId++);
    }

    /**
     *
     */
    private static void initBuildInfo() {
        // Initialize BuildInfo - using the version info from the SDK
        // You should replace this with your own build information

        final BuildInfoType buildInfo = server.getNodeManagerRoot()
                .getServerData().getServerStatus().getBuildInfo();

        // Fetch version information from the package manifest
        final Package sdkPackage = UaServer.class.getPackage();
        final String implementationVersion = sdkPackage
                .getImplementationVersion();
        if (implementationVersion != null) {
            int splitIndex = implementationVersion.lastIndexOf(".");
            final String softwareVersion = implementationVersion.substring(0,
                    splitIndex);
            String buildNumber = implementationVersion
                    .substring(splitIndex + 1);

            buildInfo.setManufacturerName(sdkPackage.getImplementationVendor());
            buildInfo.setSoftwareVersion(softwareVersion);
            buildInfo.setBuildNumber(buildNumber);
        }

        final URL classFile = UaServer.class
                .getResource("/com/prosysopc/ua/samples/SampleConsoleServer.class");
        if (classFile != null) {
            final File mfFile = new File(classFile.getFile());
            GregorianCalendar c = new GregorianCalendar();
            c.setTimeInMillis(mfFile.lastModified());
            buildInfo.setBuildDate(new DateTime(c));
        }
    }

    /**
     * @param e
     */
    private static void printException(Exception e) {
        if (stackTraceOnException) {
            e.printStackTrace();
        } else {
            println(e.toString());
            if (e.getCause() != null) {
                println("Caused by: " + e.getCause());
            }
        }
    }

    /**
     * @param string
     */
    private static void println(String string) {
        System.out.println(string);
    }

    /**
     * @return
     */
    private static Action readAction() {
        return Action.parseAction(readInput().toLowerCase());
    }

    /**
     * @return
     */
    private static String readInput() {
        BufferedReader stdin = new BufferedReader(new InputStreamReader(
                System.in));
        String s = null;
        do {
            try {
                s = stdin.readLine();
            } catch (IOException e) {
                printException(e);
            }
        } while ((s == null) || (s.length() == 0));
        return s;
    }

    /**
     * Starts the simulation of the level measurement.
     */
    private static void startSimulation() {
        simulator.scheduleAtFixedRate(simulationTask, 1000, 1000,
                TimeUnit.MILLISECONDS);
        logger.info("Simulation started.");
    }

    /**
     * Ends simulation.
     */
    private static void stopSimulation() {
        simulator.shutdown();
        logger.info("Simulation stopped.");
    }

    /*
     * Main loop for user selecting OPC UA calls
     */
    static void mainMenu() {

        /**
         * ***************************************************************************
         */
        /* Wait for user command to execute next action. */
        do {
            printMenu();

            try {
                switch (readAction()) {
                    case CLOSE:
                        return;
                    case ADD_NODE:
                        println("Enter the name of the new node (enter 'x' to cancel)");
                        String name = readInput();
                        if (!name.equals("x")) {
                            addNode(name);
                        }
                        break;
                    case DELETE_NODE:
                        println("Enter the name of the node to delete (enter 'x' to cancel)");
                        String input = readInput();
                        if (!input.equals("x")) {
                            QualifiedName nodeName = new QualifiedName(
                                    myNodeManager.getNamespaceIndex(), input);
                            deleteNode(nodeName);
                        }
                        break;
                    case ENABLE_DIAGNOSTICS:
                        final PlainProperty<Boolean> enabledFlag = server
                                .getNodeManagerRoot().getServerData()
                                .getServerDiagnostics().getEnabledFlag();
                        boolean newValue = !enabledFlag.getCurrentValue();
                        enabledFlag.setCurrentValue(newValue);
                        println("Server Diagnostics "
                                + (newValue ? "Enabled" : "Disabled"));
                        break;
                    default:
                        continue;
                }
            } catch (Exception e) {
                printException(e);
            }

        } while (true);
        /**
         * ***************************************************************************
         */
    }

    static void printMenu() {
        println("");
        println("");
        println("");
        System.out
                .println("-------------------------------------------------------");
        for (Entry<String, Action> a : Action.actionMap.entrySet()) {
            println("- Enter " + a.getKey() + " to "
                    + a.getValue().getDescription());
        }
    }
}
