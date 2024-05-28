

def get_visualizations_data():
    scheme_x = ['http', "https", "N/A"]
    scheme_y = [49500, 6303, 1133]
    domain_x = [
        '9a327404-a-62cb3a1a-s-sites.googlegroups.com',
        'installer.jdownloader.org',
        'liceulogoga.ro',
        'sites.google.com',
        'ak.imgfarm.com'
    ]
    domain_y = [283, 1013, 1064, 1243, 2760]
    top_level_domain_x = ['ru', 'br', 'org', 'net', 'com']
    top_level_domain_y = [1320, 1320, 2760, 3291, 30952]
    general_x = ['safe', 'malicious']
    general_y = [991638, 56936]
    return {
        "scheme_x": scheme_x,
        "scheme_y": scheme_y,
        "scheme_title": "Scheme Pie Chart",
        "domain_x": domain_x,
        "domain_y": domain_y,
        "domain_title": "Top Domains",
        "top_level_domain_x": top_level_domain_x,
        "top_level_domain_y": top_level_domain_y,
        "top_level_domain_title": "Top top-level domains",
        "general_x": general_x,
        "general_y": general_y,
        "general_title": "Safe vs Malicious URLs"
    }
