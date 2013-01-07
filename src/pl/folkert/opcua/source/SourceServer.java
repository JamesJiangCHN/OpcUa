package pl.folkert.opcua.source;

import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.jboss.netty.bootstrap.ServerBootstrap;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.socket.oio.OioServerSocketChannelFactory;

public class SourceServer {

    private static final ScheduledExecutorService scheduledExecutor = Executors.newSingleThreadScheduledExecutor();
    public static int currentValue = 0;
    private static final int INITIAL_DELAY = 0;
    private static final int PERIOD = 1;

    static {
	scheduledExecutor.scheduleAtFixedRate(new Runnable() {

	    int i = 0;

	    @Override
	    public void run() {
		currentValue = i++;
//		System.out.println(currentValue);
	    }
	}, INITIAL_DELAY, PERIOD, TimeUnit.MILLISECONDS);
    }

    public SourceServer(int port) {
	this.port = port;
    }
    private int port;

    public void start() {
	ServerBootstrap bootstrap = new ServerBootstrap(new OioServerSocketChannelFactory(Executors.newCachedThreadPool(), Executors.newCachedThreadPool()));

	bootstrap.setPipelineFactory(new ChannelPipelineFactory() {

	    @Override
	    public ChannelPipeline getPipeline() throws Exception {
		return Channels.pipeline(new SourceServerHandler());
	    }
	});

	bootstrap.bind(new InetSocketAddress(port));
    }

    public static void main(String[] args) {
	SourceServer server = new SourceServer(1234);
	server.start();
	System.out.println(server.getClass().getSimpleName() + " started.");
    }
}
