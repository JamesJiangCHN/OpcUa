package pl.folkert.opcua.synchro;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;

/**
 * Handler class for {@code Client}. Handles communication events on high level.
 * @version 1.0
 * @author <a href="mailto:kfolkert@3soft.pl">Kamil Folkert</a>
 */
public class SynchroClientHandler extends SimpleChannelUpstreamHandler {

    private static final Logger logger = Logger.getLogger(SynchroClientHandler.class.getName());
    private ActionListener listener;

    /**
     * Creates a client-side handler.
     */
    public SynchroClientHandler(ActionListener listener) {
        this.listener = listener;
    }

    @Override
    public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) {
    }

    @Override
    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) {
        // Send back the received message to the remote peer.
       // e.getChannel().write(e.getMessage());
        ChannelBuffer channelBuffer = (ChannelBuffer) e.getMessage();
	try {
	    listener.actionPerformed(new ActionEvent(this, channelBuffer.readInt(), "", channelBuffer.readLong(), 0));
	} catch (IndexOutOfBoundsException ex) {
	    System.err.println(ex);
	}
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) {
        logger.log(Level.WARNING, "Unexpected exception from downstream.", e.getCause());
    }
}
