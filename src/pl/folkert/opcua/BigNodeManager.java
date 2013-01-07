package pl.folkert.opcua;

import com.prosysopc.ua.StatusException;
import com.prosysopc.ua.ValueRanks;
import com.prosysopc.ua.nodes.UaNode;
import com.prosysopc.ua.nodes.UaReference;
import com.prosysopc.ua.nodes.UaReferenceType;
import com.prosysopc.ua.nodes.UaVariable;
import com.prosysopc.ua.server.IoManager;
import com.prosysopc.ua.server.MonitoredDataItem;
import com.prosysopc.ua.server.MonitoredItem;
import com.prosysopc.ua.server.NodeManager;
import com.prosysopc.ua.server.ServiceContext;
import com.prosysopc.ua.server.Subscription;
import com.prosysopc.ua.server.UaServer;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.log4j.Logger;
import org.opcfoundation.ua.builtintypes.DataValue;
import org.opcfoundation.ua.builtintypes.DateTime;
import org.opcfoundation.ua.builtintypes.ExpandedNodeId;
import org.opcfoundation.ua.builtintypes.LocalizedText;
import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.builtintypes.QualifiedName;
import org.opcfoundation.ua.builtintypes.StatusCode;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
import org.opcfoundation.ua.builtintypes.Variant;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.AccessLevel;
import org.opcfoundation.ua.core.Attributes;
import org.opcfoundation.ua.core.Identifiers;
import org.opcfoundation.ua.core.NodeClass;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.core.TimestampsToReturn;
import org.opcfoundation.ua.utils.NumericRange;
import pl.folkert.opcua.source.SourceClient;
import pl.folkert.opcua.synchro.SynchroClient;

/**
 * A sample implementation of a NodeManager which does not use UaNode objects,
 * but connects to an underlying system for the data.
 */
public class BigNodeManager extends NodeManager {

    protected static final Logger logger = Logger.getLogger(BigNodeManager.class.getCanonicalName());

    @Override
    public NodeId getVariableDataType(NodeId nodeid) throws StatusException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean hasNode(NodeId nodeid) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public class DataItem {

        private final String name;
        private StatusCode status = new StatusCode(StatusCodes.Bad_WaitingForInitialData);
        private DateTime timestamp;
        private double value;

        /**
         * @param name
         * @param value
         */
        public DataItem(String name) {
            super();
            this.name = name;
        }

        /**
         *
         */
        public void getDataValue(DataValue dataValue) {
            dataValue.setValue(new Variant(getValue()));
            dataValue.setStatusCode(getStatus());
            dataValue.setServerTimestamp(DateTime.currentTime());
            dataValue.setSourceTimestamp(timestamp);
        }

        /**
         * @return the name
         */
        public String getName() {
            return name;
        }

        /**
         * @return the status
         */
        public StatusCode getStatus() {
            return status;
        }

        /**
         * The timestamp defined when the value or status changed.
         *
         * @return the timestamp
         */
        public DateTime getTimestamp() {
            return timestamp;
        }

        /**
         * @return the value
         */
        public double getValue() {
            return value;
        }

        /**
         * @param value the value to set
         */
        public void setValue(double value) {
            setValue(value, StatusCode.GOOD);
        }

        /**
         * @param value the value to set
         * @param status the status to set
         */
        public void setValue(double value, StatusCode status) {
            if (status == null) {
                status = StatusCode.BAD;
            }
            if ((this.value != value) || !this.status.equals(status)) {
                this.value = value;
                this.status = status;
                this.timestamp = DateTime.currentTime();
            }
        }
    }

    /**
     * An IO Manager which provides the values for the attributes of the nodes.
     */
    public class BigIoManager extends IoManager {

        /**
         * Constructor for the IoManager.
         *
         * @param nodeManager the node manager that uses this IO Manager.
         */
        public BigIoManager(NodeManager nodeManager) {
            super(nodeManager);
        }

        @Override
        protected void readNonValue(ServiceContext serviceContext,
                NodeId nodeId, UaNode node, UnsignedInteger attributeId,
                DataValue dataValue) throws StatusException {
            Object value = null;
            final ExpandedNodeId expandedNodeId = getNamespaceTable()
                    .toExpandedNodeId(nodeId);
            if (attributeId.equals(Attributes.NodeId)) {
                value = nodeId;
            } else if (attributeId.equals(Attributes.BrowseName)) {
                value = getBrowseName(expandedNodeId, node);
            } else if (attributeId.equals(Attributes.DisplayName)) {
                value = getDisplayName(expandedNodeId, node, null);
            } else if (attributeId.equals(Attributes.Description)) {
                value = "";
            } else if (attributeId.equals(Attributes.NodeClass)) {
                value = getNodeClass(expandedNodeId, node);
            } else if (attributeId.equals(Attributes.WriteMask)) {
                value = UnsignedInteger.ZERO;
            } // the following are only requested for the DataItems
            else if (attributeId.equals(Attributes.DataType)) {
                value = Identifiers.Double;
            } else if (attributeId.equals(Attributes.ValueRank)) {
                value = ValueRanks.Scalar;
            } else if (attributeId.equals(Attributes.ArrayDimensions)) {
                value = -1;
            } else if (attributeId.equals(Attributes.AccessLevel)) {
                value = AccessLevel.getMask(AccessLevel.READONLY);
            } else if (attributeId.equals(Attributes.Historizing)) {
                value = false;
            } else if (attributeId.equals(Attributes.MinimumSamplingInterval)) {
                value = 0;
            }

            dataValue.setValue(new Variant(value));
            dataValue.setStatusCode(value == null ? StatusCode.BAD
                    : StatusCode.GOOD);
            dataValue.setServerTimestamp(DateTime.currentTime());
        }

        @Override
        protected void readValue(ServiceContext serviceContext, NodeId nodeId,
                UaVariable node, NumericRange indexRange,
                TimestampsToReturn timestampsToReturn, DateTime minTimestamp,
                DataValue dataValue) throws StatusException {
            DataItem dataItem = getDataItem(nodeId);
            if (dataItem == null) {
                throw new StatusException(StatusCodes.Bad_NodeIdInvalid);
            }
            dataItem.getDataValue(dataValue);
        }
    }

    /**
     *
     */
    public class MyReference extends UaReference {

        private final NodeId referenceTypeId;
        private final ExpandedNodeId sourceId;
        private final ExpandedNodeId targetId;

        /**
         * @param sourceId
         * @param targetId
         * @param referenceType
         */
        public MyReference(ExpandedNodeId sourceId, ExpandedNodeId targetId,
                NodeId referenceType) {
            super();
            this.sourceId = sourceId;
            this.targetId = targetId;
            this.referenceTypeId = referenceType;
        }

        /**
         * @param sourceId
         * @param targetId
         * @param referenceType
         */
        public MyReference(NodeId sourceId, NodeId targetId,
                NodeId referenceType) {
            this(getNamespaceTable().toExpandedNodeId(sourceId),
                    getNamespaceTable().toExpandedNodeId(targetId),
                    referenceType);
        }

        @Override
        public void delete() {
            throw new RuntimeException("StatusCodes.Bad_NotImplemented");
        }

        @Override
        public boolean getIsInverse(NodeId nodeId) {
            try {
                if (nodeId.equals(getNamespaceTable().toNodeId(sourceId))) {
                    return false;
                }
                if (nodeId.equals(getNamespaceTable().toNodeId(targetId))) {
                    return true;
                }
            } catch (ServiceResultException e) {
                throw new RuntimeException(e);
            }
            throw new RuntimeException("not a source nor target");
        }

        @Override
        public boolean getIsInverse(UaNode node) {
            return getIsInverse(node.getNodeId());
        }

        @Override
        public UaReferenceType getReferenceType() {
            try {
                return (UaReferenceType) getNodeManagerTable().getNode(
                        getReferenceTypeId());
            } catch (StatusException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public NodeId getReferenceTypeId() {
            return referenceTypeId;
        }

        @Override
        public ExpandedNodeId getSourceId() {
            return sourceId;
        }

        @Override
        public UaNode getSourceNode() {
            return null; // new UaExternalNodeImpl(myNodeManager, sourceId);
        }

        @Override
        public ExpandedNodeId getTargetId() {
            return targetId;
        }

        @Override
        public UaNode getTargetNode() {
            return null; // new UaExternalNodeImpl(myNodeManager, targetId);
        }
    }

    private class SamplingTask implements Runnable {

        public SamplingTask() {
        }
        private ActionListener actionListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (server.isRunning()) {
                    Integer value = e.getID();
                    BigNodeManager.this.setValues(value);
//			for (CacheVariable node : intObjects) {
//			    node.updateValue(value);
//			}
                }
            }
        };
        final SourceClient sourceClient = new SourceClient(Common.SOURCE_SERVER_HOST, Common.SOURCE_SERVER_PORT, actionListener);

        public SourceClient getSourceClient() {
            return sourceClient;
        }

        @Override
        public void run() {
            sourceClient.sample();
        }
    }
    private static ExpandedNodeId DataItemType;
    private final ExpandedNodeId DataItemFolder;
    private final Map<String, DataItem> dataItems;
    private final Map<String, Collection<MonitoredDataItem>> monitoredItems = new ConcurrentHashMap<>();
    private final HashMap<NodeId, ScheduledExecutorService> schedulers = new HashMap<>();
    private final HashMap<NodeId, SamplingTask> samplingTasks = new HashMap<>();
    private final HashMap<ScheduledExecutorService, SamplingTask> waitingSchedulers = new HashMap<>();
    private final HashMap<ScheduledExecutorService, Integer> waitingIntervals = new HashMap<>();
    private UaServer server;

    /**
     * Default constructor
     *
     * @param server the UaServer, which owns the NodeManager
     * @param namespaceUri the namespace which this node manager handles
     * @param nofItems number of data items to create for the manager
     */
    public BigNodeManager(UaServer server, String namespaceUri, int nofItems) {
        super(server, namespaceUri);
        this.server = server;
        DataItemType = new ExpandedNodeId(null, getNamespaceIndex(),
                "DataItemType");
        DataItemFolder = new ExpandedNodeId(null, getNamespaceIndex(),
                "DataItemFolder");
        try {
            getNodeManagerTable()
                    .getNodeManagerRoot()
                    .getObjectsFolder()
                    .addReference(getNamespaceTable().toNodeId(DataItemFolder),
                    Identifiers.Organizes, false);
        } catch (ServiceResultException e) {
            throw new RuntimeException(e);
        }
        dataItems = new HashMap<>(nofItems);
        for (int i = 0; i < nofItems; i++) {
            addDataItem(String.format("DataItem_%04d", i));
        }

    }
    private SynchroClient synchroClient = new SynchroClient(Common.SYNCHRO_SERVER_HOST, Common.SYNCHRO_SERVER_PORT, new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            int waitingTasks = waitingSchedulers.keySet().size();
            Set<ScheduledExecutorService> keySet = new HashSet(waitingSchedulers.keySet());
            for (ScheduledExecutorService sourceScheduler : keySet) {
                Integer interval = waitingIntervals.remove(sourceScheduler);
                if (interval != null) {
                    sourceScheduler.scheduleAtFixedRate(waitingSchedulers.remove(sourceScheduler), interval, interval, TimeUnit.MILLISECONDS);
                }
            }
            if (waitingTasks > 0) {
                System.out.println(waitingTasks + " sampling task(s) started.");
            }
            System.err.println(System.currentTimeMillis());
        }
    });
    private SamplingTask samplingTask = null;

    private void startSampling(MonitoredDataItem item) {

        if (samplingTask == null) {
            samplingTask = new SamplingTask();
            samplingTasks.put(item.getNodeId(), samplingTask);

            ScheduledExecutorService sourceScheduler = schedulers.get(item.getNodeId());
            if (sourceScheduler == null) {
                sourceScheduler = Executors.newSingleThreadScheduledExecutor();
                schedulers.put(item.getNodeId(), sourceScheduler);
            }
            waitingSchedulers.put(sourceScheduler, samplingTask);
            waitingIntervals.put(sourceScheduler, (int) item.getSamplingInterval());
        }

    }

    private void stopSampling(MonitoredDataItem item) {
        SamplingTask removedTask = samplingTasks.remove(item.getNodeId());
        if (removedTask != null) {
            removedTask.getSourceClient().disconnect();
        }
        ScheduledExecutorService removedService = schedulers.remove(item.getNodeId());
        if (removedService != null) {
            removedService.shutdown();
        }
    }

    public void shutdown() {
        Set<NodeId> keySet = new HashSet(schedulers.keySet());
        for (NodeId item : keySet) {
            schedulers.remove(item).shutdown();
            samplingTasks.remove(item).getSourceClient().disconnect();
        }
        server.shutdown(1, new LocalizedText("Closed by user", Locale.ENGLISH));
        synchroClient.disconnect();
    }

    /**
     * @param name
     */
    private void addDataItem(String name) {
        dataItems.put(name, new DataItem(name));
    }

    /**
     * Finds the DataItem corresponding to the NodeId
     *
     * @param nodeId ID of the node - the Value part corresponds to the name of
     * the item
     * @return the DataItem object
     */
    private DataItem getDataItem(ExpandedNodeId nodeId) {
        String name = (String) nodeId.getValue();
        return dataItems.get(name);
    }

    /**
     * Finds the DataItem corresponding to the NodeId
     *
     * @param nodeId ID of the node - the Value part corresponds to the name of
     * the item
     * @return the DataItem object
     */
    private DataItem getDataItem(NodeId nodeId) {
        String name = (String) nodeId.getValue();
        return dataItems.get(name);
    }

    /**
     * @param nodeId
     * @return
     */
    private String getNodeName(ExpandedNodeId nodeId) {
        String name = nodeId.getValue().toString();
        if (getNamespaceTable().nodeIdEquals(nodeId, DataItemType)) {
            name = "DataItemType";
        }
        if (getNamespaceTable().nodeIdEquals(nodeId, DataItemFolder)) {
            name = "DataItemFolder";
        } else {
            DataItem dataItem = getDataItem(nodeId);
            // Use the namespaceIndex of the NodeManager name space also for the
            // browse names
            if (dataItem != null) {
                name = dataItem.getName();
            }
        }
        return name;
    }

    /**
     * Send a data change notification for all monitored data items that are
     * monitoring the dataItme
     *
     * @param dataItem
     */
    private void notifyMonitoredDataItems(DataItem dataItem) {
        // Get the list of items watching dataItem
        Collection<MonitoredDataItem> c = monitoredItems.get(dataItem.getName());
        if (c != null) {
            for (MonitoredDataItem item : c) {
                DataValue dataValue = new DataValue();
                dataItem.getDataValue(dataValue);
                item.onDataChange(null, null, dataValue);
            }
        }
    }

    @Override
    protected void afterCreateMonitoredDataItem(ServiceContext serviceContext,
            Subscription subscription, MonitoredDataItem item) {
        // Add all items that monitor the same node to the same collection
        final String dataItemName = item.getNodeId().getValue().toString();
        Collection<MonitoredDataItem> c = monitoredItems.get(dataItemName);
        if (c == null) {
            c = new CopyOnWriteArrayList<>();
            monitoredItems.put(dataItemName, c);
        }
        c.add(item);
        if (item.getSamplingInterval() <= 0.0d) {
            item.setSamplingInterval(1.0d);
        }
        startSampling(item);
        logger.info("afterCreateMonitoredDataItem\t"
                + "nodeId=" + item.getNodeId() + "\tc.size()=" + c.size());
    }

    @Override
    protected void deleteMonitoredItem(ServiceContext serviceContext,
            Subscription subscription, MonitoredItem item)
            throws StatusException {
        // Find the collection in which the monitoredItem is
        // and remove the item from the collection
        String itemNodeId = item.getNodeId().toString();
        Collection<MonitoredDataItem> c = monitoredItems.get(item.getNodeId().getValue().toString());
        if (c != null) {
            c.remove((MonitoredDataItem) item);
            if (c.isEmpty()) {
                monitoredItems.remove(item.getNodeId().getValue().toString());
            }
        }
        stopSampling((MonitoredDataItem) item);
        logger.info("deleteMonitoredItem\t"
                + "nodeId=" + itemNodeId + "\tc.size()=" + c.size());
    }

    @Override
    protected QualifiedName getBrowseName(ExpandedNodeId nodeId, UaNode node) {
        final String name = getNodeName(nodeId);
        return new QualifiedName(getNamespaceIndex(), name);
    }

    @Override
    protected LocalizedText getDisplayName(ExpandedNodeId nodeId,
            UaNode targetNode, Locale locale) {
        final String name = getNodeName(nodeId);
        return new LocalizedText(name, LocalizedText.NO_LOCALE);
    }

    @Override
    protected NodeClass getNodeClass(ExpandedNodeId nodeId, UaNode node) {
        if (getNamespaceTable().nodeIdEquals(nodeId, DataItemType)) {
            return NodeClass.VariableType;
        }
        if (getNamespaceTable().nodeIdEquals(nodeId, DataItemFolder)) {
            return NodeClass.Object;
        }
        // All data items are variables
        return NodeClass.Variable;
    }

    @Override
    protected UaReference[] getReferences(NodeId nodeId, UaNode node) {
        try {
            // Define reference to our type
            if (nodeId.equals(getNamespaceTable().toNodeId(DataItemType))) {
                return new UaReference[]{new MyReference(new ExpandedNodeId(
                            Identifiers.BaseDataVariableType), DataItemType,
                            Identifiers.HasSubtype)};
            }
            // Define reference from and to our Folder for the DataItems
            if (nodeId.equals(getNamespaceTable().toNodeId(DataItemFolder))) {
                UaReference[] folderItems = new UaReference[dataItems.size() + 2];
                // Inverse reference to the ObjectsFolder
                folderItems[0] = new MyReference(new ExpandedNodeId(
                        Identifiers.ObjectsFolder), DataItemFolder,
                        Identifiers.Organizes);
                // Type definition reference
                folderItems[1] = new MyReference(DataItemFolder,
                        getTypeDefinition(
                        getNamespaceTable().toExpandedNodeId(nodeId),
                        node), Identifiers.HasTypeDefinition);
                int i = 2;
                // Reference to all items in the folder
                for (DataItem d : dataItems.values()) {
                    folderItems[i] = new MyReference(DataItemFolder,
                            new ExpandedNodeId(null, getNamespaceIndex(),
                            d.getName()), Identifiers.HasComponent);
                    i++;
                }
                return folderItems;
            }
        } catch (ServiceResultException e) {
            throw new RuntimeException(e);
        }

        // Define references from our DataItems
        DataItem dataItem = getDataItem(nodeId);
        if (dataItem == null) {
            return null;
        }
        final ExpandedNodeId dataItemId = new ExpandedNodeId(null,
                getNamespaceIndex(), dataItem.getName());
        return new UaReference[]{
                    // Inverse reference to the folder
                    new MyReference(DataItemFolder, dataItemId,
                    Identifiers.HasComponent),
                    // Type definition
                    new MyReference(dataItemId, DataItemType,
                    Identifiers.HasTypeDefinition)};
    }

    @Override
    protected ExpandedNodeId getTypeDefinition(ExpandedNodeId nodeId,
            UaNode node) {
        // ExpandedNodeId.equals cannot be trusted, since some IDs are defined
        // with NamespaceIndex while others use NamespaceUri
        if (getNamespaceTable().nodeIdEquals(nodeId, DataItemType)) {
            return null;
        }
        if (getNamespaceTable().nodeIdEquals(nodeId, DataItemFolder)) {
            return getNamespaceTable().toExpandedNodeId(Identifiers.FolderType);
        }
        return DataItemType;
    }

    public void setValues(double value) {
        for (DataItem d : dataItems.values()) {
            d.setValue(value);
            notifyMonitoredDataItems(d);
        }
    }
}
