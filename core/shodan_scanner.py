import shodan

def get_shodan_info(target_ip, api_key):
    api = shodan.Shodan(api_key)

    try:
        # Recherche de l'IP sur Shodan
        host = api.search(target_ip)

        info = {
            "IP" : host['ip_str'],
            "os_shodan": host.get('os', 'n/a'),
            "ports_count" : len(host.get('ports', [])),
            "ports" : host.get('ports', []),
            "is_cloud" : "Cloud" in host.get('org', 'n/a'),
            "shodan_tags" : host.get('tags', [])
        }
        return info

    except shodan.APIError as e:
        print(f"[!] Error Shodan: {e}")
        return None