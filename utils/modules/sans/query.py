"""
SANS query module - handles API communication
"""
import aiohttp
import logging
import xml.etree.ElementTree as ET
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


async def query_sans_async(ip: str) -> Optional[Dict[str, Any]]:
    """
    Query SANS Internet Storm Center for IP information.
    Note: SANS API returns XML, not JSON.

    Args:
        ip (str): The IP address to query.

    Returns:
        dict: Raw API response data.
        None: If an error occurs.
    """
    try:
        url = f"https://isc.sans.edu/api/ip/{ip}"  
        logger.info(f"Querying SANS for IP: {ip}")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    # SANS API returns XML, not JSON
                    xml_text = await response.text()
                    logger.debug(f"SANS XML response received: {xml_text[:200]}")
                    
                    # Parse XML
                    try:
                        root = ET.fromstring(xml_text)
                        data = {}
                        
                        # Extract all fields from XML
                        for child in root:
                            tag = child.tag
                            text = child.text if child.text else ""
                            # Convert empty strings to None for numeric fields
                            if tag in ['count', 'attacks', 'maxrisk', 'as', 'assize']:
                                data[tag] = int(text) if text and text.strip() else 0
                            elif tag == 'threatfeeds':
                                # Parse threatfeeds - structured XML with feed names as sub-elements
                                # Example: <threatfeeds><nokia><lastseen>...</lastseen></nokia></threatfeeds>
                                threatfeeds_list = []
                                # Check if threatfeeds has sub-elements (feed names)
                                for feed_elem in child:
                                    feed_name = feed_elem.tag
                                    # Feed is considered active if it has sub-elements like lastseen/firstseen
                                    # or if it has text content
                                    has_data = False
                                    if feed_elem.text and feed_elem.text.strip():
                                        has_data = True
                                    else:
                                        # Check for sub-elements (like lastseen, firstseen)
                                        for sub_elem in feed_elem:
                                            if sub_elem.text and sub_elem.text.strip():
                                                has_data = True
                                                break
                                    
                                    if has_data:
                                        threatfeeds_list.append(feed_name)
                                
                                if threatfeeds_list:
                                    data[tag] = threatfeeds_list
                                else:
                                    data[tag] = []
                            else:
                                data[tag] = text.strip() if text else ""
                        
                        # Also get the IP number
                        if root.find('number') is not None:
                            data['ip'] = root.find('number').text if root.find('number').text else ip
                        else:
                            data['ip'] = ip
                        
                        logger.info(f"SANS data parsed successfully for {ip}")
                        return {
                            "raw_data": data,
                            "ip": ip
                        }
                    except ET.ParseError as e:
                        logger.error(f"Error parsing SANS XML for {ip}: {e}")
                        logger.debug(f"XML content: {xml_text[:500]}")
                        return None
                else:
                    logger.warning(f"SANS API returned status {response.status}")
                    return None

    except aiohttp.ClientError as e:
        logger.error(f"Network error querying SANS for {ip}: {e}")
    except Exception as e:
        logger.error(f"Error querying SANS for {ip}: {e}", exc_info=True)

    return None

