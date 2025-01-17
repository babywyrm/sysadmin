import os
import yaml
import json
import logging

##
##

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_file):
    """Load the configuration from a JSON or YAML file."""
    with open(config_file, 'r') as f:
        if config_file.endswith('.json'):
            return json.load(f)
        elif config_file.endswith('.yaml') or config_file.endswith('.yml'):
            return yaml.safe_load(f)
        else:
            raise ValueError("Unsupported config file format. Use JSON or YAML.")

def refactor_helm_chart(chart_dir, new_chart_dir, config):
    """Refactor a Helm chart located in chart_dir and save it to new_chart_dir."""
    if not os.path.exists(new_chart_dir):
        os.makedirs(new_chart_dir)

    # Copy values.yaml and modify it
    values_file = os.path.join(chart_dir, 'values.yaml')
    if os.path.exists(values_file):
        with open(values_file, 'r') as f:
            values = yaml.safe_load(f)

        # Apply modifications based on the config
        for key, value in config.get('values', {}).items():
            if value is None:  # If value is None, remove the key
                values.pop(key, None)
            else:
                values[key] = value

        # Save the modified values.yaml
        with open(os.path.join(new_chart_dir, 'values.yaml'), 'w') as f:
            yaml.dump(values, f)
            logging.info(f"Updated values.yaml with modifications: {config.get('values', {})}")

    # Copy templates and modify them
    templates_dir = os.path.join(chart_dir, 'templates')
    if os.path.exists(templates_dir):
        new_templates_dir = os.path.join(new_chart_dir, 'templates')
        os.makedirs(new_templates_dir, exist_ok=True)

        for template_file in os.listdir(templates_dir):
            if template_file.endswith('.yaml'):
                with open(os.path.join(templates_dir, template_file), 'r') as f:
                    content = f.read()

                # Apply modifications based on the config
                for placeholder, new_value in config.get('templates', {}).items():
                    if new_value is None:  # If new_value is None, remove the placeholder
                        content = content.replace(f'{{{{ .Values.{placeholder} }}}}', '')
                    else:
                        content = content.replace(f'{{{{ .Values.{placeholder} }}}}', new_value)

                # Save the modified template
                with open(os.path.join(new_templates_dir, template_file), 'w') as f:
                    f.write(content)
                    logging.info(f"Updated template {template_file} with modifications.")

    logging.info(f"Refactored Helm chart saved to {new_chart_dir}")

if __name__ == "__main__":
    # Example usage
    original_chart_directory = "path/to/original/chart"
    refactored_chart_directory = "path/to/refactored/chart"
    config_file = "path/to/config.yaml"  # Configuration file with modifications

    try:
        config = load_config(config_file)
        refactor_helm_chart(original_chart_directory, refactored_chart_directory, config)
    except Exception as e:
        logging.error(f"Error during refactoring: {e}")

##
##
##
## values:
##   newKey: newValue
##   oldKey: null  # This will remove oldKey from values.yaml
##
## templates:
##   oldPlaceholder: newValue  # Replace oldPlaceholder with newValue
##   anotherPlaceholder: null   # This will remove anotherPlaceholder from templates
##
##
##
