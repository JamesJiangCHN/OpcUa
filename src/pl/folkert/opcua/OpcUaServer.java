package pl.folkert.opcua;

import com.prosysopc.ua.ApplicationIdentity;
import com.prosysopc.ua.CertificateValidationListener;
import com.prosysopc.ua.PkiFileBasedCertificateValidator;
import com.prosysopc.ua.PkiFileBasedCertificateValidator.CertificateCheck;
import com.prosysopc.ua.PkiFileBasedCertificateValidator.ValidationResult;
import com.prosysopc.ua.SecureIdentityException;
import com.prosysopc.ua.StatusException;
import com.prosysopc.ua.UserIdentity;
import com.prosysopc.ua.nodes.UaNode;
import com.prosysopc.ua.nodes.UaNodeFactoryException;
import com.prosysopc.ua.nodes.UaReference;
import com.prosysopc.ua.nodes.UaReferenceType;
import com.prosysopc.ua.server.MonitoredDataItem;
import com.prosysopc.ua.server.NodeManagerListener;
import com.prosysopc.ua.server.NodeManagerUaNode;
import com.prosysopc.ua.server.ServiceContext;
import com.prosysopc.ua.server.Session;
import com.prosysopc.ua.server.Subscription;
import com.prosysopc.ua.server.UaServer;
import com.prosysopc.ua.server.UaServerException;
import com.prosysopc.ua.server.UserValidator;
import com.prosysopc.ua.server.nodes.PlainProperty;
import com.prosysopc.ua.server.nodes.opcua.BuildInfoType;
import com.prosysopc.ua.server.nodes.opcua.FolderType;
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
import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.opcfoundation.ua.builtintypes.DateTime;
import org.opcfoundation.ua.builtintypes.ExpandedNodeId;
import org.opcfoundation.ua.builtintypes.LocalizedText;
import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.builtintypes.QualifiedName;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
import org.opcfoundation.ua.builtintypes.Variant;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.AggregateFilterResult;
import org.opcfoundation.ua.core.ApplicationDescription;
import org.opcfoundation.ua.core.Identifiers;
import org.opcfoundation.ua.core.MonitoringFilter;
import org.opcfoundation.ua.core.MonitoringParameters;
import org.opcfoundation.ua.core.NodeAttributes;
import org.opcfoundation.ua.core.NodeClass;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.core.UserTokenPolicy;
import org.opcfoundation.ua.core.UserTokenType;
import org.opcfoundation.ua.core.ViewDescription;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.SecurityMode;

public class OpcUaServer {

    public OpcUaServer(int port, String name, int itemsCount) throws CertificateExpiredException, CertificateNotYetValidException, IOException, InvalidKeySpecException, SecureIdentityException, StatusException, UaServerException {

        final PkiFileBasedCertificateValidator validator = new PkiFileBasedCertificateValidator();
        validator.setValidationListener(validationListener);

        ApplicationDescription appDescription = new ApplicationDescription();
        appDescription.setApplicationName(new LocalizedText(APP_NAME, Locale.ENGLISH));
        appDescription.setApplicationUri("urn:localhost:UA:SampleConsoleServer");
        appDescription.setProductUri("urn:prosysopc.com:UA:SampleConsoleServer");

        final ApplicationIdentity identity = ApplicationIdentity.loadOrCreateCertificate(appDescription, "EkDan",
                /* Private Key Password */ "opcua",
                /* Key File Path */ new File(validator.getBaseDir(), "private"),
                /* Enable renewing the certificate */ true);

        server.setApplicationIdentity(identity);
        server.setPort(port);
        server.setUseLocalhost(false);
        server.setServerName(name);
        server.setUseAllIpAddresses(false);
        server.setSecurityModes(SecurityMode.ALL);
        server.addUserTokenPolicy(UserTokenPolicy.ANONYMOUS);
        server.setUserValidator(userValidator);

        server.init();

        initBuildInfo();
        createAddressSpace(itemsCount);

        server.start();

    }

    private enum Action {

        ADD_NODE("add a new node"),
        CLOSE("close the server"),
        DELETE_NODE("delete a node"),
        ENABLE_DIAGNOSTICS("enable/disable server diagnostics");
        static final Map<String, Action> actionMap = new HashMap<>();

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
    ArrayList<UaNode> nodes = new ArrayList<>();
    
    private static final String APP_NAME = "SampleConsoleServer";
    private static Logger logger = Logger.getLogger(OpcUaServer.class);
    
    private NodeManagerUaNode myNodeManager;
    
    private NodeManagerListener myNodeManagerListener = new NodeManagerListener() {
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
            checkUserIdentity(serviceContext);
        }

        @Override
        public void onAfterCreateMonitoredDataItem(ServiceContext serviceContext, Subscription subscription, MonitoredDataItem item) {
        }

        @Override
        public void onAfterDeleteMonitoredDataItem(ServiceContext serviceContext, Subscription subscription, MonitoredDataItem item) {
        }

        @Override
        public void onAfterModifyMonitoredDataItem(ServiceContext serviceContext, Subscription subscription, MonitoredDataItem item) {
        }

        @Override
        public boolean onBrowseNode(ServiceContext serviceContext, ViewDescription view, NodeId nodeId, UaNode node, UaReference reference) {
            return true;
        }

        @Override
        public void onCreateMonitoredDataItem(ServiceContext serviceContext, Subscription subscription, UaNode node, UnsignedInteger attributeId, String indexRange, MonitoringParameters params, MonitoringFilter filter, AggregateFilterResult filterResult) throws StatusException {
        }

        @Override
        public void onDeleteMonitoredDataItem(ServiceContext serviceContext, Subscription subscription, MonitoredDataItem monitoredItem) {
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
            if (serviceContext.getSession().getUserIdentity().getType().equals(UserTokenType.Anonymous)) {
                throw new StatusException(StatusCodes.Bad_UserAccessDenied);
            }
        }
    };
    private FolderType myObjectsFolder;
    private UserValidator userValidator = new UserValidator() {
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
    private CertificateValidationListener validationListener = new CertificateValidationListener() {
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
                                + PkiFileBasedCertificateValidator.getApplicationUriOfCertificate(certificate));
                    } catch (CertificateParsingException e) {
                        throw new RuntimeException(e);
                    }
                }
                return ValidationResult.AcceptPermanently;
            }
            return ValidationResult.Reject;
        }
    };
    protected Variant[] eventFieldValues;
    protected Object eventSender;
    private UaServer server = new UaServer();
    
    public UaServer getServer() {
        return server;
    }

    public UserValidator getUserValidator() {
        return userValidator;
    }

    public Object getEventSender() {
        return eventSender;
    }

    public NodeManagerListener getNodeManagerListener() {
        return myNodeManagerListener;
    }

    private void addNode(String name) {
        // Initialize NodeVersion property, to enable ModelChangeEvents
        myObjectsFolder.initNodeVersion();

        server.getNodeManagerRoot().beginModelChange();
        try {
            NodeId nodeId = new NodeId(myNodeManager.getNamespaceIndex(), UUID.randomUUID());
            UaNode node = myNodeManager.getNodeFactory().createNode(NodeClass.Variable, nodeId, name, Locale.ENGLISH, Identifiers.PropertyType);
            myObjectsFolder.addComponent(node);
        } catch (UaNodeFactoryException e) {
            logger.error(e);
        } finally {
            server.getNodeManagerRoot().endModelChange();
        }
    }

    private void createAddressSpace(int itemsCount) throws StatusException {
        myNodeManager = new NodeManagerUaNode(server,
                "http://www.prosysopc.com/OPCUA/SampleAddressSpace");

        myNodeManager.addListener(myNodeManagerListener);

        createBigNodeManager(itemsCount);

        myBigNodeManager.addListener(myNodeManagerListener);
        logger.info("Address space created.");
    }
    /**
     * Create a sample node manager, which does not use UaNode objects. These
     * are suitable for managing big address spaces for data that is in practice
     * available from another existing subsystem.
     */
    private BigNodeManager myBigNodeManager;

    public BigNodeManager getMyBigNodeManager() {
        return myBigNodeManager;
    }

    private void createBigNodeManager(int items) {
        myBigNodeManager = new BigNodeManager(server,
                "http://www.prosysopc.com/OPCUA/SampleBigAddressSpace", items);
    }

    private void deleteNode(QualifiedName nodeName) throws StatusException {
        UaNode node = myObjectsFolder.getComponent(nodeName);
        if (node != null) {
            server.getNodeManagerRoot().beginModelChange();
            try {
                myNodeManager.deleteNode(node, true, true);
            } finally {
                server.getNodeManagerRoot().endModelChange();
            }
        } else {
            println("Folder does not contain a component with name " + nodeName);
        }
    }

    private void initBuildInfo() {

        final BuildInfoType buildInfo = server.getNodeManagerRoot().getServerData().getServerStatus().getBuildInfo();

        final Package sdkPackage = UaServer.class.getPackage();
        final String implementationVersion = sdkPackage.getImplementationVersion();
        if (implementationVersion != null) {
            int splitIndex = implementationVersion.lastIndexOf(".");
            final String softwareVersion = implementationVersion.substring(0, splitIndex);
            String buildNumber = implementationVersion.substring(splitIndex + 1);

            buildInfo.setManufacturerName(sdkPackage.getImplementationVendor());
            buildInfo.setSoftwareVersion(softwareVersion);
            buildInfo.setBuildNumber(buildNumber);
        }

        final URL classFile = UaServer.class.getResource("/com/prosysopc/ua/samples/SampleConsoleServer.class");
        if (classFile != null) {
            final File mfFile = new File(classFile.getFile());
            GregorianCalendar c = new GregorianCalendar();
            c.setTimeInMillis(mfFile.lastModified());
            buildInfo.setBuildDate(new DateTime(c));
        }
    }

    @SuppressWarnings("CallToThreadDumpStack")
    private void printException(Exception e) {
        e.printStackTrace();
    }

    private void println(String string) {
        System.out.println(string);
    }

    private Action readAction() {
        return Action.parseAction(readInput().toLowerCase());
    }

    private String readInput() {
        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
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

    public void mainMenu() {
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
                            QualifiedName nodeName = new QualifiedName(myNodeManager.getNamespaceIndex(), input);
                            deleteNode(nodeName);
                        }
                        break;
                    case ENABLE_DIAGNOSTICS:
                        final PlainProperty<Boolean> enabledFlag = server.getNodeManagerRoot().getServerData().getServerDiagnostics().getEnabledFlag();
                        boolean newValue = !enabledFlag.getCurrentValue();
                        enabledFlag.setCurrentValue(newValue);
                        println("Server Diagnostics " + (newValue ? "Enabled" : "Disabled"));
                        break;
                    default:
                        continue;
                }
            } catch (Exception e) {
                printException(e);
            }

        } while (true);
    }

    public void printMenu() {
        println("");
        println("");
        println("");
        System.out.println("-------------------------------------------------------");
        for (Entry<String, Action> a : Action.actionMap.entrySet()) {
            println("- Enter " + a.getKey() + " to " + a.getValue().getDescription());
        }
    }

    public static void main(String[] args) throws IOException, InvalidKeySpecException, SecureIdentityException, URISyntaxException, ServiceResultException, StatusException, CertificateNotYetValidException, CertificateExpiredException, UaServerException {
        PropertyConfigurator.configure(OpcUaServer.class.getResource("log.properties"));

        OpcUaServer opcUaServer = null;
        if (args.length == 0 || args[0].equals("primary")) {
            opcUaServer = new OpcUaServer(Common.PRIMARY_UA_SERVER_PORT, Common.PRIMARY_UA_SERVER_NAME, Common.ITEMS_COUNT);
        } else if (args[0].equals("secondary")) {
            opcUaServer = new OpcUaServer(Common.SECONDARY_UA_SERVER_PORT, Common.SECONDARY_UA_SERVER_NAME, Common.ITEMS_COUNT);
        }

        opcUaServer.mainMenu();

        System.out.println("Shutting down...");
        opcUaServer.getMyBigNodeManager().shutdown();
        System.out.println("Closed.");
        System.exit(1);
    }
}
