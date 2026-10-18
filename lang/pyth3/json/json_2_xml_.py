################
################


def json2xml(json_obj, tag_name=None):
    result_list = list()

    json_obj_type = type(json_obj)

    if json_obj_type is list:
        for sub_elem in json_obj:
            result_list.append("\n<%s>" % (tag_name))
            result_list.append(json2xml(sub_elem, tag_name=tag_name))
            tag_name = re.sub('\s\w+="\w+"', '', tag_name)
            result_list.append("</%s>" % (tag_name))

        return "".join(result_list)

    if json_obj_type is dict:
        for tag_name in json_obj:
            sub_obj = json_obj[tag_name]
            if isinstance(sub_obj, list):
                result_list.append(json2xml(sub_obj, tag_name=tag_name))
            elif isinstance(sub_obj, dict):
                result_list.append("\n<%s>" % (tag_name))
                result_list.append(json2xml(sub_obj, tag_name=tag_name))
                result_list.append("\n</%s>" % (tag_name))
            else:
                result_list.append("\n<%s>" % (tag_name))
                result_list.append(json2xml(sub_obj, tag_name=tag_name))
                tag_name = re.sub('\s\w+="\w+"', '', tag_name)
                result_list.append("</%s>" % (tag_name))

        return "".join(result_list)

    return "%s" % json_obj
    

################
################
