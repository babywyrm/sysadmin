To search for all Docker images derived from a particular Ubuntu Bionic image in a target repository using Python, you can use the Docker SDK for Python.

Here's an example Python class that uses the SDK to search for images:

```
import docker

class DockerImageSearcher:
    def __init__(self):
        self.client = docker.from_env()

    def search_images(self, base_image, target_repo):
        # Get a list of all images in the target repository
        all_images = self.client.images.list(target_repo)

        # Search for images that have the base image as their parent
        derived_images = []
        for image in all_images:
            if base_image in image.attrs["Parent"]:
                derived_images.append(image)

        # Print the names of the derived images
        for image in derived_images:
            print(image.tags)
            
```         

In this example class, we define a DockerImageSearcher class that has an __init__ method that creates a Docker client object using docker.from_env().

The search_images method takes in a base_image and target_repo parameter, and uses the Docker client object to get a list of all images in the target repository. It then loops through all of the images and checks if the base image is in the image's parent attribute (which represents the image that this image was created from). If the base image is in the parent attribute, it appends the image to a list of derived images.

Finally, the method loops through the list of derived images and prints their tags. You can modify the class to perform other actions on the derived images, such as pulling or deleting them.

To use this class to search for all images derived from a particular Ubuntu Bionic image in a target repository, you can create an instance of the DockerImageSearcher class and call its search_images method:


```
searcher = DockerImageSearcher()
searcher.search_images("ubuntu:bionic", "target-repository")
This will search for all Docker images derived from the ubuntu:bionic base image in the target-repository repository and print their tags.
