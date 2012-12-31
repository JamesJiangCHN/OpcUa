package pl.folkert.opcua;

import java.util.Collection;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

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

/**
 * A sample implementation of a NodeManager which does not use UaNode objects,
 * but connects to an underlying system for the data.
 */
public class MyBigNodeManager extends NodeManager {

	public class DataItem {
		private final String name;
		private StatusCode status = new StatusCode(
				StatusCodes.Bad_WaitingForInitialData);
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
		 * @param value
		 *            the value to set
		 */
		public void setValue(double value) {
			setValue(value, StatusCode.GOOD);
		}

		/**
		 * @param value
		 *            the value to set
		 * @param status
		 *            the status to set
		 */
		public void setValue(double value, StatusCode status) {
			if (status == null)
				status = StatusCode.BAD;
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
	public class MyBigIoManager extends IoManager {

		/**
		 * Constructor for the IoManager.
		 * 
		 * @param nodeManager
		 *            the node manager that uses this IO Manager.
		 */
		public MyBigIoManager(NodeManager nodeManager) {
			super(nodeManager);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * com.prosysopc.ua.server.IoManager#readNonValue(com.prosysopc.ua.server
		 * .ServiceContext, org.opcfoundation.ua.builtintypes.NodeId,
		 * com.prosysopc.ua.nodes.UaNode,
		 * org.opcfoundation.ua.builtintypes.UnsignedInteger,
		 * org.opcfoundation.ua.builtintypes.DataValue)
		 */
		@Override
		protected void readNonValue(ServiceContext serviceContext,
				NodeId nodeId, UaNode node, UnsignedInteger attributeId,
				DataValue dataValue) throws StatusException {
			Object value = null;
			final ExpandedNodeId expandedNodeId = getNamespaceTable()
					.toExpandedNodeId(nodeId);
			if (attributeId.equals(Attributes.NodeId))
				value = nodeId;
			else if (attributeId.equals(Attributes.BrowseName))
				value = getBrowseName(expandedNodeId, node);
			else if (attributeId.equals(Attributes.DisplayName))
				value = getDisplayName(expandedNodeId, node, null);
			else if (attributeId.equals(Attributes.Description))
				value = null;
			else if (attributeId.equals(Attributes.NodeClass))
				value = getNodeClass(expandedNodeId, node);
			else if (attributeId.equals(Attributes.WriteMask))
				value = UnsignedInteger.ZERO;
			// the following are only requested for the DataItems
			else if (attributeId.equals(Attributes.DataType))
				value = Identifiers.Double;
			else if (attributeId.equals(Attributes.ValueRank))
				value = ValueRanks.OneDimension;
			else if (attributeId.equals(Attributes.ArrayDimensions))
				value = null;
			else if (attributeId.equals(Attributes.AccessLevel))
				value = AccessLevel.getMask(AccessLevel.READONLY);
			else if (attributeId.equals(Attributes.Historizing))
				value = false;

			dataValue.setValue(new Variant(value));
			dataValue.setStatusCode(value == null ? StatusCode.BAD
					: StatusCode.GOOD);
			dataValue.setServerTimestamp(DateTime.currentTime());
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * com.prosysopc.ua.server.IoManager#readValue(com.prosysopc.ua.server
		 * .ServiceContext, org.opcfoundation.ua.builtintypes.NodeId,
		 * com.prosysopc.ua.nodes.UaVariable,
		 * org.opcfoundation.ua.utils.NumericRange,
		 * org.opcfoundation.ua.core.TimestampsToReturn,
		 * org.opcfoundation.ua.builtintypes.DateTime,
		 * org.opcfoundation.ua.builtintypes.DataValue)
		 */
		@Override
		protected void readValue(ServiceContext serviceContext, NodeId nodeId,
				UaVariable node, NumericRange indexRange,
				TimestampsToReturn timestampsToReturn, DateTime minTimestamp,
				DataValue dataValue) throws StatusException {
			DataItem dataItem = getDataItem(nodeId);
			if (dataItem == null)
				throw new StatusException(StatusCodes.Bad_NodeIdInvalid);
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

		/*
		 * (non-Javadoc)
		 * 
		 * @see com.prosysopc.ua.nodes.UaReference#delete()
		 */
		@Override
		public void delete() {
			throw new RuntimeException("StatusCodes.Bad_NotImplemented");
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * com.prosysopc.ua.nodes.UaReference#getIsInverse(org.opcfoundation
		 * .ua.builtintypes.NodeId)
		 */
		@Override
		public boolean getIsInverse(NodeId nodeId) {
			try {
				if (nodeId.equals(getNamespaceTable().toNodeId(sourceId)))
					return false;
				if (nodeId.equals(getNamespaceTable().toNodeId(targetId)))
					return true;
			} catch (ServiceResultException e) {
				throw new RuntimeException(e);
			}
			throw new RuntimeException("not a source nor target");
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * com.prosysopc.ua.nodes.UaReference#getIsInverse(com.prosysopc.ua.
		 * nodes.UaNode)
		 */
		@Override
		public boolean getIsInverse(UaNode node) {
			return getIsInverse(node.getNodeId());
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see com.prosysopc.ua.nodes.UaReference#getReferenceType()
		 */
		@Override
		public UaReferenceType getReferenceType() {
			try {
				return (UaReferenceType) getNodeManagerTable().getNode(
						getReferenceTypeId());
			} catch (StatusException e) {
				throw new RuntimeException(e);
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see com.prosysopc.ua.nodes.UaReference#getReferenceTypeId()
		 */
		@Override
		public NodeId getReferenceTypeId() {
			return referenceTypeId;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see com.prosysopc.ua.nodes.UaReference#getSourceId()
		 */
		@Override
		public ExpandedNodeId getSourceId() {
			return sourceId;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see com.prosysopc.ua.nodes.UaReference#getSourceNode()
		 */
		@Override
		public UaNode getSourceNode() {
			return null; // new UaExternalNodeImpl(myNodeManager, sourceId);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see com.prosysopc.ua.nodes.UaReference#getTargetId()
		 */
		@Override
		public ExpandedNodeId getTargetId() {
			return targetId;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see com.prosysopc.ua.nodes.UaReference#getTargetNode()
		 */
		@Override
		public UaNode getTargetNode() {
			return null; // new UaExternalNodeImpl(myNodeManager, targetId);
		}

	}

	private static ExpandedNodeId DataItemType;

	private final ExpandedNodeId DataItemFolder;

	private final Map<String, DataItem> dataItems;

	private final Map<String, Collection<MonitoredDataItem>> monitoredItems = new ConcurrentHashMap<String, Collection<MonitoredDataItem>>();

	private final MyBigIoManager myBigIoManager;

	private double t = 0;

	/**
	 * Default constructor
	 * 
	 * @param server
	 *            the UaServer, which owns the NodeManager
	 * @param namespaceUri
	 *            the namespace which this node manager handles
	 * @param nofItems
	 *            number of data items to create for the manager
	 */
	public MyBigNodeManager(UaServer server, String namespaceUri, int nofItems) {
		super(server, namespaceUri);
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
		dataItems = new HashMap<String, MyBigNodeManager.DataItem>(nofItems);
		for (int i = 0; i < nofItems; i++)
			addDataItem(String.format("DataItem_%04d", i));

		myBigIoManager = new MyBigIoManager(this);
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
	 * @param nodeId
	 *            ID of the node - the Value part corresponds to the name of the
	 *            item
	 * @return the DataItem object
	 */
	private DataItem getDataItem(ExpandedNodeId nodeId) {
		String name = (String) nodeId.getValue();
		return dataItems.get(name);
	}

	/**
	 * Finds the DataItem corresponding to the NodeId
	 * 
	 * @param nodeId
	 *            ID of the node - the Value part corresponds to the name of the
	 *            item
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
		if (getNamespaceTable().nodeIdEquals(nodeId, DataItemType))
			name = "DataItemType";
		if (getNamespaceTable().nodeIdEquals(nodeId, DataItemFolder))
			name = "DataItemFolder";
		else {
			DataItem dataItem = getDataItem(nodeId);
			// Use the namespaceIndex of the NodeManager name space also for the
			// browse names
			if (dataItem != null)
				name = dataItem.getName();
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
		Collection<MonitoredDataItem> c = monitoredItems
				.get(dataItem.getName());
		if (c != null)
			for (MonitoredDataItem item : c) {
				DataValue dataValue = new DataValue();
				dataItem.getDataValue(dataValue);
				item.onDataChange(null, null, dataValue);
			}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.prosysopc.ua.server.NodeManager#afterCreateMonitoredDataItem(com.
	 * prosysopc.ua.server.ServiceContext, com.prosysopc.ua.server.Subscription,
	 * com.prosysopc.ua.server.MonitoredDataItem)
	 */
	@Override
	protected void afterCreateMonitoredDataItem(ServiceContext serviceContext,
			Subscription subscription, MonitoredDataItem item) {
		// Add all items that monitor the same node to the same collection
		final Object dataItemName = item.getNodeId().getValue();
		Collection<MonitoredDataItem> c = monitoredItems.get(dataItemName);
		if (c == null) {
			c = new CopyOnWriteArrayList<MonitoredDataItem>();
			monitoredItems.put((String) dataItemName, c);
		}
		c.add(item);
		System.out.println("nodeId=" + item.getNodeId() + "c.size()="
				+ c.size());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.prosysopc.ua.server.NodeManager#deleteMonitoredItem(com.prosysopc
	 * .ua.server.ServiceContext, com.prosysopc.ua.server.Subscription,
	 * com.prosysopc.ua.server.MonitoredItem)
	 */
	@Override
	protected void deleteMonitoredItem(ServiceContext serviceContext,
			Subscription subscription, MonitoredItem item)
			throws StatusException {
		// Find the collection in which the monitoredItem is
		// and remove the item from the collection
		Collection<MonitoredDataItem> c = monitoredItems.get(item.getNodeId());
		if (c != null) {
			c.remove(item);
			if (c.isEmpty())
				monitoredItems.remove(item.getNodeId());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.prosysopc.ua.server.NodeManager#getBrowseName(org.opcfoundation.ua
	 * .builtintypes.ExpandedNodeId, com.prosysopc.ua.nodes.UaNode)
	 */
	@Override
	protected QualifiedName getBrowseName(ExpandedNodeId nodeId, UaNode node) {
		final String name = getNodeName(nodeId);
		return new QualifiedName(getNamespaceIndex(), name);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.prosysopc.ua.server.NodeManager#getDisplayName(org.opcfoundation.
	 * ua.builtintypes.ExpandedNodeId, com.prosysopc.ua.nodes.UaNode,
	 * java.util.Locale)
	 */
	@Override
	protected LocalizedText getDisplayName(ExpandedNodeId nodeId,
			UaNode targetNode, Locale locale) {
		final String name = getNodeName(nodeId);
		return new LocalizedText(name, LocalizedText.NO_LOCALE);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.prosysopc.ua.server.NodeManager#getNodeClass(org.opcfoundation.ua
	 * .builtintypes.ExpandedNodeId, com.prosysopc.ua.nodes.UaNode)
	 */
	@Override
	protected NodeClass getNodeClass(ExpandedNodeId nodeId, UaNode node) {
		if (getNamespaceTable().nodeIdEquals(nodeId, DataItemType))
			return NodeClass.VariableType;
		if (getNamespaceTable().nodeIdEquals(nodeId, DataItemFolder))
			return NodeClass.Object;
		// All data items are variables
		return NodeClass.Variable;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.prosysopc.ua.server.NodeManager#getReferences(org.opcfoundation.ua
	 * .builtintypes.NodeId, com.prosysopc.ua.nodes.UaNode)
	 */
	@Override
	protected UaReference[] getReferences(NodeId nodeId, UaNode node) {
		try {
			// Define reference to our type
			if (nodeId.equals(getNamespaceTable().toNodeId(DataItemType)))
				return new UaReference[] { new MyReference(new ExpandedNodeId(
						Identifiers.BaseDataVariableType), DataItemType,
						Identifiers.HasSubtype) };
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
		if (dataItem == null)
			return null;
		final ExpandedNodeId dataItemId = new ExpandedNodeId(null,
				getNamespaceIndex(), dataItem.getName());
		return new UaReference[] {
				// Inverse reference to the folder
				new MyReference(DataItemFolder, dataItemId,
						Identifiers.HasComponent),
				// Type definition
				new MyReference(dataItemId, DataItemType,
						Identifiers.HasTypeDefinition) };
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.prosysopc.ua.server.NodeManager#getTypeDefinition(org.opcfoundation
	 * .ua.builtintypes.ExpandedNodeId, com.prosysopc.ua.nodes.UaNode)
	 */
	@Override
	protected ExpandedNodeId getTypeDefinition(ExpandedNodeId nodeId,
			UaNode node) {
		// ExpandedNodeId.equals cannot be trusted, since some IDs are defined
		// with NamespaceIndex while others use NamespaceUri
		if (getNamespaceTable().nodeIdEquals(nodeId, DataItemType))
			return null;
		if (getNamespaceTable().nodeIdEquals(nodeId, DataItemFolder))
			return getNamespaceTable().toExpandedNodeId(Identifiers.FolderType);
		return DataItemType;
	}

	void simulate() {
		t = t + Math.PI / 180;
		double value = 100 * Math.sin(t);
		for (DataItem d : dataItems.values()) {
			d.setValue(value);
			notifyMonitoredDataItems(d);
		}
	}

}
