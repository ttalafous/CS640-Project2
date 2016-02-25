package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	
    Map<Object, Iface> macInterfaces = new HashMap<Object, Iface>();
    Map<Object, Integer> toDelete = new HashMap<Object, Integer>();

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/

		// Manage deletion map
		if(!toDelete.containsKey(etherPacket.getSourceMAC())) {
		    toDelete.put(etherPacket.getSourceMAC(), 0);
		}
		else {
		    toDelete.put(etherPacket.getSourceMAC(), toDelete.get(etherPacket.getSourceMAC()) + 1);
		}

		// Add MAC to route map
		macInterfaces.put(etherPacket.getSourceMAC(), inIface);
		final Object mac = etherPacket.getSourceMAC();
		final int check = toDelete.get(etherPacket.getSourceMAC());

		// DETECTION OF RESET WORKS BUT COULD BE BETTER

		new java.util.Timer().schedule(
					       new java.util.TimerTask() {
						   @Override
						   public void run() {
						       if(toDelete.get(mac) == check) {
							   macInterfaces.remove(mac);
							   System.out.println("Removed an entry!\n");
						       }
						       else {
							   System.out.println("NOPE\n");
						       }
						   }
					       },
					       15000);

		// Print currently learned entries
		System.out.println("\nCurrent learned entries:\n");
		for(Map.Entry<Object, Iface> entry : macInterfaces.entrySet()) {
		    System.out.println("\t" + entry.getKey() + " : " + entry.getValue());
		}
		System.out.println();

		if(macInterfaces.containsKey(etherPacket.getDestinationMAC())) {
		    System.out.println("Found learned MAC : Interface\n" + etherPacket.getDestinationMAC() + " : " + macInterfaces.get(etherPacket.getDestinationMAC()) + "\n");
		    if(!sendPacket(etherPacket, macInterfaces.get(etherPacket.getDestinationMAC()))) {
			System.out.println("Thought MAC was learned, but error occurred!\n");
		    }
		    return;
		}
		else {
		    for(Map.Entry<String, Iface> entry : getInterfaces().entrySet()) {
			System.out.println("Sending:\t" + etherPacket.getDestinationMAC()+ " : " + entry.getValue());
			if(sendPacket(etherPacket, entry.getValue())) {
			    System.out.println("WORKED\n");
			}
		    }
		    return;
		}

		/********************************************************************/
	}
}
