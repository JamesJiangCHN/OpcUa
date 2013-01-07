package pl.folkert.opcua.synchro;

import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

import org.jboss.netty.bootstrap.ServerBootstrap;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.socket.oio.OioServerSocketChannelFactory;

public class SynchroServer {

    public SynchroServer(int port) {
	this.port = port;
    }
    private int port;

    public void start() {
	// Configure the server.
	ServerBootstrap bootstrap = new ServerBootstrap(
			    new OioServerSocketChannelFactory(
			    Executors.newCachedThreadPool(),
			    Executors.newCachedThreadPool()));

	// Set up the pipeline factory.
	bootstrap.setPipelineFactory(new ChannelPipelineFactory() {

            private SynchroServerHandler synchroServerHandler = new SynchroServerHandler();
	    @Override
	    public ChannelPipeline getPipeline() throws Exception {
		return Channels.pipeline(synchroServerHandler);
	    }
	});

	// Bind and start to accept incoming connections.
	bootstrap.bind(new InetSocketAddress(port));
    }

    public static void main(String[] args) {
	SynchroServer server = new SynchroServer(8888);
	server.start();
	System.out.println(server.getClass().getSimpleName() + " started.");
    }
}
