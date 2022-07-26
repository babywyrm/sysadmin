def func1(data):
    for key,value in data.items():
        print (str(key)+'->'+str(value))
        if isinstance(value, dict):
            func1(value)
        elif isinstance(value, list):
            for val in value:
                if isinstance(val, str):
                    pass
                elif isinstance(val, list):
                    pass
                else:
                    func1(val)
func1(sample)

#########################
##
##
