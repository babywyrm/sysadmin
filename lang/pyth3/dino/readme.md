

Lists,

```
# Example 1: Function to calculate the square of each element in a list
def calculate_squares(numbers):
    return [x**2 for x in numbers]

numbers = [1, 2, 3, 4, 5]
squares = calculate_squares(numbers)
print("Squares of numbers:", squares)

# Example 2: Function to filter dinosaurs based on life expectancy threshold
def filter_dinosaurs_by_life_expectancy(dinosaur_info_dict, threshold):
    return [dino for dino, age in dinosaur_info_dict.items() if age > threshold]

threshold = 25
long_lived_dinosaurs = filter_dinosaurs_by_life_expectancy(dinosaur_info_dict, threshold)
print(f"Dinosaurs with life expectancies greater than {threshold} years:", long_lived_dinosaurs)
```

Dictionaries,

```
# Example 1: Function to create a dictionary mapping dinosaurs to their life expectancies
def create_dinosaur_info_dict(dinosaur_names, life_expectancies):
    return {dino: age for dino, age in zip(dinosaur_names, life_expectancies)}

dinosaur_names = ['Tyrannosaurus', 'Stegosaurus', 'Triceratops', 'Velociraptor']
life_expectancies = [30, 25, 35, 20]
dinosaur_info_dict = create_dinosaur_info_dict(dinosaur_names, life_expectancies)
print("Dictionary mapping dinosaurs to their life expectancies:", dinosaur_info_dict)

# Example 2: Function to filter dinosaurs based on life expectancy threshold and diet
def filter_dinosaurs(dinosaur_info_dict, threshold, diet):
    return {dino: age for dino, age in dinosaur_info_dict.items() if age > threshold and dinosaur_diets[dino] == diet}

threshold = 25
diet = 'herbivore'
long_lived_herbivores = filter_dinosaurs(dinosaur_info_dict, threshold, diet)
print(f"Herbivorous dinosaurs with life expectancies greater than {threshold} years:", long_lived_herbivores)
```




##
##



We'll create lists and dictionaries containing information about dinosaurs using comprehensions.

List Comprehension Examples with Dinosaurs:

```
# Example 1: Create a list of dinosaur names
dinosaur_names = ['Tyrannosaurus', 'Stegosaurus', 'Triceratops', 'Velociraptor', 'Brachiosaurus', 'Ankylosaurus', 'Allosaurus', 'Diplodocus', 'Pteranodon', 'Spinosaurus', 'Parasaurolophus', 'Iguanodon', 'Brontosaurus', 'Carcharodontosaurus', 'Archaeopteryx', 'Ceratosaurus', 'Gallimimus', 'Therizinosaurus', 'Troodon', 'Dilophosaurus', 'Deinonychus', 'Plateosaurus']

# Example 2: Create a list of dinosaurs with life expectancies greater than 25 years
dinosaur_info = {
    'Tyrannosaurus': 30,
    'Stegosaurus': 25,
    'Triceratops': 35,
    'Velociraptor': 20,
    'Brachiosaurus': 40,
    'Ankylosaurus': 30,
    'Allosaurus': 28,
    'Diplodocus': 35,
    'Pteranodon': 25,
    'Spinosaurus': 32,
    'Parasaurolophus': 28,
    'Iguanodon': 27,
    'Brontosaurus': 35,
    'Carcharodontosaurus': 30,
    'Archaeopteryx': 3,
    'Ceratosaurus': 28,
    'Gallimimus': 25,
    'Therizinosaurus': 30,
    'Troodon': 20,
    'Dilophosaurus': 25,
    'Deinonychus': 30,
    'Plateosaurus': 30
}

dinosaur_names_greater_than_25_years = [dino for dino, age in dinosaur_info.items() if age > 25]
print("Dinosaurs with life expectancies greater than 25 years:", dinosaur_names_greater_than_25_years)
Dictionary Comprehension Examples with Dinosaurs:


# Example 1: Create a dictionary mapping dinosaurs to their life expectancies
dinosaur_info_dict = {
    'Tyrannosaurus': 30,
    'Stegosaurus': 25,
    'Triceratops': 35,
    'Velociraptor': 20,
    'Brachiosaurus': 40,
    'Ankylosaurus': 30,
    'Allosaurus': 28,
    'Diplodocus': 35,
    'Pteranodon': 25,
    'Spinosaurus': 32,
    'Parasaurolophus': 28,
    'Iguanodon': 27,
    'Brontosaurus': 35,
    'Carcharodontosaurus': 30,
    'Archaeopteryx': 3,
    'Ceratosaurus': 28,
    'Gallimimus': 25,
    'Therizinosaurus': 30,
    'Troodon': 20,
    'Dilophosaurus': 25,
    'Deinonychus': 30,
    'Plateosaurus': 30
}

dinosaur_info_dict_comp = {dino: age for dino, age in dinosaur_info.items()}
print("Dictionary mapping dinosaurs to their life expectancies:", dinosaur_info_dict_comp)

# Example 2: Create a dictionary mapping dinosaurs to boolean values indicating if their life expectancy is greater than 25 years
dinosaur_life_expectancy_over_25_dict = {dino: age > 25 for dino, age in dinosaur_info.items()}
print("Dictionary mapping dinosaurs to boolean values if their life expectancy is greater than 25 years:", dinosaur_life_expectancy_over_25_dict)

```
