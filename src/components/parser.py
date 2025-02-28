import json
import pandas as pd

def load_wpscan_json(wpscan_input):
    data = json.load(wpscan_input)

    host = data["target_url"]

    # 1. WordPress Version Data
    wordpress_version = {
        "number": data["wordpress_version"]["number"],
        "status": data["wordpress_version"]["status"],
        "vulnerabilities": [
            {
                "id": v["id"],
                "title": v["title"],
                "fixed_in": v["fixed_in"],
                "references": ', '.join(v["references"]["url"])  # Join URLs if there are multiple
            }
            for v in data["wordpress_version"]["vulnerabilities"]
        ]
    }

    # Create DataFrame for WordPress version and vulnerabilities
    df_wordpress_version = pd.DataFrame(wordpress_version["vulnerabilities"])
    df_wordpress_version["wordpress_version"] = wordpress_version["number"]
    df_wordpress_version["wordpress_status"] = wordpress_version["status"]

    # 2. Plugins Data
    plugins = []
    for plugin in data["plugins"]:
        for vulnerability in plugin["vulnerabilities"]:
            plugins.append({
                "plugin_name": plugin["name"],
                "plugin_version": plugin["version"],
                "plugin_status": plugin["status"],
                "vulnerability_id": vulnerability["id"],
                "vulnerability_title": vulnerability["title"],
                "vulnerability_fixed_in": vulnerability["fixed_in"],
                "vulnerability_references": ', '.join(vulnerability["references"]["url"])
            })
        # If no vulnerabilities, still add plugin data
        if not plugin["vulnerabilities"]:
            plugins.append({
                "plugin_name": plugin["name"],
                "plugin_version": plugin["version"],
                "plugin_status": plugin["status"],
                "vulnerability_id": None,
                "vulnerability_title": None,
                "vulnerability_fixed_in": None,
                "vulnerability_references": None
            })

    df_plugins = pd.DataFrame(plugins)

    # 3. Themes Data
    themes = [{
        "theme_name": theme["name"],
        "theme_version": theme["version"],
        "theme_status": theme["status"]
    } for theme in data["themes"]]

    df_themes = pd.DataFrame(themes)

    # 4. Users Data
    df_users = pd.DataFrame(data["users"])

    # 5. Interesting Findings Data
    interesting_findings = [{
        "finding_type": finding["type"],
        "finding_description": finding["description"]
    } for finding in data["interesting_findings"]]

    df_interesting_findings = pd.DataFrame(interesting_findings)

    vulnerabilities = []

    # Extract vulnerabilities from the WordPress version
    for vuln in data.get("wordpress_version", {}).get("vulnerabilities", []):
        vulnerabilities.append({
            "component": "WordPress",
            "name": "WordPress",
            "version": data["wordpress_version"]["number"],
            "vulnerability_id": vuln["id"],
            "title": vuln["title"],
            "fixed_in": vuln["fixed_in"],
            "reference_url": vuln["references"]["url"][0] if "url" in vuln["references"] else None
        })

    # Extract vulnerabilities from the plugins
    for plugin in data.get("plugins", []):
        for vuln in plugin.get("vulnerabilities", []):
            vulnerabilities.append({
                "component": "Plugin",
                "name": plugin['name'],
                "version": plugin["version"],
                "vulnerability_id": vuln["id"],
                "title": vuln["title"],
                "fixed_in": vuln["fixed_in"],
                "reference_url": vuln["references"]["url"][0] if "url" in vuln["references"] else None
            })

    # Extract vulnerabilities from the themes
    for theme in data.get("themes", []):
        for vuln in theme.get("vulnerabilities", []):
            vulnerabilities.append({
                "component": "Themes",
                "name": theme['name'],
                "version": theme["version"],
                "vulnerability_id": vuln["id"],
                "title": vuln["title"],
                "fixed_in": vuln["fixed_in"],
                "reference_url": vuln["references"]["url"][0] if "url" in vuln["references"] else None
            })

    # Extract vulnerabilities

    # Create DataFrame
    df_vulnerabilities = pd.DataFrame(vulnerabilities)
    print(df_vulnerabilities)

    # Print the dataframes to see the result
    print("Target URL:")
    print(host)
    print("WordPress Version Data:")
    print(df_wordpress_version)
    print("\nPlugins Data:")
    print(df_plugins)
    print("\nThemes Data:")
    print(df_themes)
    print("\nUsers Data:")
    print(df_users)
    print("\nInteresting Findings Data:")
    print(df_interesting_findings)

    return host,df_wordpress_version, df_plugins, df_users, df_interesting_findings, df_themes, df_vulnerabilities