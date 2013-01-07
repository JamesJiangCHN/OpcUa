package pl.folkert.opcua.source;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jboss.netty.bootstrap.ClientBootstrap;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.socket.oio.OioClientSocketChannelFactory;

/**
 * TCP communication client class.
 * @version 1.0
 * @author <a href="mailto:kfolkert@3soft.pl">Kamil Folkert</a>
 */
public class SourceClient {

    private Channel channel;
    private ClientBootstrap bootstrap = new ClientBootstrap(new OioClientSocketChannelFactory(Executors.newCachedThreadPool()));

    public SourceClient(String host, int port, final ActionListener actionListener) {

	// Set up the pipeline factory.
	bootstrap.setPipelineFactory(new ChannelPipelineFactory() {

	    @Override
	    public ChannelPipeline getPipeline() throws Exception {
		return Channels.pipeline(new SourceClientHandler(actionListener));
	    }
	});

	// Start the connection attempt.
	ChannelFuture future = bootstrap.connect(new InetSocketAddress(host, port));

	channel = future.getChannel();
    }

    public void disconnect() {
	channel.disconnect();
	bootstrap.releaseExternalResources();

    }

    public void sample() {
	ChannelBuffer channelBuffer = ChannelBuffers.buffer(4);
	channelBuffer.writeInt(SourceMessage.GET.ordinal());
	try {
	    channel.write(channelBuffer);
	} catch (Exception ex) {
	    System.err.println(ex.getLocalizedMessage());
	}
    }

    public static void main(String[] args) {
	SourceClient client = new SourceClient("localhost", 1234, new ActionListener() {

	    @Override
	    public void actionPerformed(ActionEvent e) {
		System.out.println("Value: " + e.getID() + "\tTimestamp: " + e.getWhen());
	    }
	});

	while (true) {
	    client.sample();
	    try {
		Thread.sleep(100);
	    } catch (InterruptedException ex) {
		Logger.getLogger(SourceClient.class.getName()).log(Level.SEVERE, null, ex);
	    }
	}
	//client.disconnect();
    }
}
