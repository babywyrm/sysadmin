
##
##

dinosaur_info = {
    'Tyrannosaurus': {'life_expectancy': 30, 'diet': 'carnivore'},
    'Stegosaurus': {'life_expectancy': 25, 'diet': 'herbivore'},
    'Triceratops': {'life_expectancy': 35, 'diet': 'herbivore'},
    'Velociraptor': {'life_expectancy': 20, 'diet': 'carnivore'},
    'Brachiosaurus': {'life_expectancy': 40, 'diet': 'herbivore'},
    'Ankylosaurus': {'life_expectancy': 30, 'diet': 'herbivore'},
    'Allosaurus': {'life_expectancy': 28, 'diet': 'carnivore'},
    'Diplodocus': {'life_expectancy': 35, 'diet': 'herbivore'},
    'Pteranodon': {'life_expectancy': 25, 'diet': 'carnivore'},
    'Spinosaurus': {'life_expectancy': 32, 'diet': 'carnivore'},
    'Parasaurolophus': {'life_expectancy': 28, 'diet': 'herbivore'},
    'Iguanodon': {'life_expectancy': 27, 'diet': 'herbivore'},
    'Brontosaurus': {'life_expectancy': 35, 'diet': 'herbivore'},
    'Carcharodontosaurus': {'life_expectancy': 30, 'diet': 'carnivore'},
    'Archaeopteryx': {'life_expectancy': 3, 'diet': 'carnivore'},
    'Ceratosaurus': {'life_expectancy': 28, 'diet': 'carnivore'},
    'Allosaurus': {'life_expectancy': 28, 'diet': 'carnivore'},
    'Gallimimus': {'life_expectancy': 25, 'diet': 'herbivore'},
    'Therizinosaurus': {'life_expectancy': 30, 'diet': 'herbivore'},
    'Troodon': {'life_expectancy': 20, 'diet': 'carnivore'},
    'Dilophosaurus': {'life_expectancy': 25, 'diet': 'carnivore'},
    'Deinonychus': {'life_expectancy': 30, 'diet': 'carnivore'},
    'Plateosaurus': {'life_expectancy': 30, 'diet': 'herbivore'}
}

def find_long_lived_dinosaurs(dinosaur_dict, life_expectancy_threshold, diet):
    return [dino for dino, info in dinosaur_dict.items() if info['life_expectancy'] > life_expectancy_threshold and info['diet'] == diet]

# Examples with different thresholds and diets
thresholds = [25, 30, 35, 40]
diets = ['carnivore', 'herbivore']

for threshold in thresholds:
    for diet in diets:
        long_lived_dinosaurs = find_long_lived_dinosaurs(dinosaur_info, threshold, diet)
        print(f"Dinosaurs with a life expectancy greater than {threshold} years and diet '{diet}':", long_lived_dinosaurs)

# Sorting the dictionary based on life expectancy
sorted_dinosaur_info_life = {k: v for k, v in sorted(dinosaur_info.items(), key=lambda item: item[1]['life_expectancy'], reverse=True)}
print("\nDinosaurs sorted by life expectancy:", sorted_dinosaur_info_life)

# Sorting the dictionary based on diet
sorted_dinosaur_info_diet = {k: v for k, v in sorted(dinosaur_info.items(), key=lambda item: item[1]['diet'])}
print("\nDinosaurs sorted by diet:", sorted_dinosaur_info_diet)

# Sorting the dictionary based on life expectancy and diet
sorted_dinosaur_info_combined = {k: v for k, v in sorted(dinosaur_info.items(), key=lambda item: (item[1]['diet'], item[1]['life_expectancy']))}
print("\nDinosaurs sorted by diet and life expectancy:", sorted_dinosaur_info_combined)

##
##
