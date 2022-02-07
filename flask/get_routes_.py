
from werkzeug.utils import import_string

############
############
##

@admin_api.route('/help', methods=['GET'])
def routes_info():
    """Print all defined routes and their endpoint docstrings

    This also handles flask-router, which uses a centralized scheme
    to deal with routes, instead of defining them as a decorator
    on the target function.
    """
    routes = []
    for rule in app.url_map.iter_rules():
        try:
            if rule.endpoint != 'static':
                if hasattr(app.view_functions[rule.endpoint], 'import_name'):
                    import_name = app.view_functions[rule.endpoint].import_name
                    obj = import_string(import_name)
                    routes.append({rule.rule: "%s\n%s" % (",".join(list(rule.methods)), obj.__doc__)})
                else:
                    routes.append({rule.rule: app.view_functions[rule.endpoint].__doc__})
        except Exception as exc:
            routes.append({rule.rule: 
                           "(%s) INVALID ROUTE DEFINITION!!!" % rule.endpoint})
            route_info = "%s => %s" % (rule.rule, rule.endpoint)
            app.logger.error("Invalid route: %s" % route_info, exc_info=True)
            # func_list[rule.rule] = obj.__doc__

    return jsonify(code=200, data=routes)
  
  ##################################
  ##
##
