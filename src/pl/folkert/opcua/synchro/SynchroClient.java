package pl.folkert.opcua.synchro;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import org.jboss.netty.bootstrap.ClientBootstrap;
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
public class SynchroClient {
    
    private Channel channel;
    private ClientBootstrap bootstrap;

    public SynchroClient(String host, int port, final ActionListener actionListener) {
        bootstrap = new ClientBootstrap(
                new OioClientSocketChannelFactory(Executors.newCachedThreadPool()));

        // Set up the pipeline factory.
        bootstrap.setPipelineFactory(new ChannelPipelineFactory() {

            @Override
            public ChannelPipeline getPipeline() throws Exception {
                return Channels.pipeline(new SynchroClientHandler(actionListener));
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

    public static void main(String[] args) {
        SynchroClient client = new SynchroClient("localhost", 1234, new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                System.out.println(e.getWhen() + " " + SynchroMessage.fromInt(e.getID()).name());
            }
        });
    }
}
