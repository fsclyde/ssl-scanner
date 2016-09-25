#################################################
#
#  models
#
#################################################
from flask_restful import reqparse, abort, Api, Resource, fields
from flask_restful_swagger import swagger


# SSL scan model parameters			
@swagger.model
class SslModel:
	def __init__(self, url, description, filter, skipcache):
		pass

# SSL compliance
@swagger.model
class ComplianceModel:
	def __init__(self, url, showdetails, skipcache):
		pass

# Vulnerability scan model parameters			
@swagger.model
class VulnModel:
  def __init__(self, service): 
    pass
    
# Arachni scan model parameters			
@swagger.model
class ArachniModel:
  def __init__(self, scan_url, description): 
    pass

@swagger.model
class ModelWithResourceFields:
	resource_fields = {
	  'a_url': fields.Url()
	}
	resource_fields = {
	  'a_string': fields.String()
	}

#################################################
@swagger.model
class ModelWithResourceFields:
  resource_fields = {
      'a_string': fields.String(),
      'a_url': fields.Url()
  }


#################################################


@swagger.model
@swagger.nested(
   a_nested_attribute=ModelWithResourceFields.__name__,
   a_list_of_nested_types=ModelWithResourceFields.__name__)
class TodoItemWithResourceFields:
	
  resource_fields = {
      'a_string': fields.String(attribute='a_string_field_name'),
      'a_formatted_string': fields.FormattedString,
      'an_int': fields.Integer,
      'a_bool': fields.Boolean,
      'a_url': fields.Url,
      'a_float': fields.Float,
      'an_float_with_arbitrary_precision': fields.Arbitrary,
      'a_fixed_point_decimal': fields.Fixed,
      'a_datetime': fields.DateTime,
      'a_list_of_strings': fields.List(fields.String),
      'a_nested_attribute': fields.Nested(ModelWithResourceFields.resource_fields),
      'a_list_of_nested_types': fields.List(fields.Nested(ModelWithResourceFields.resource_fields)),
  }

  # Specify which of the resource fields are required
  required = ['a_string']
