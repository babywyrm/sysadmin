

##
##

dinosaur_info = {
    'Tyrannosaurus': {'life_expectancy': 30, 'diet': 'carnivore', 'period': 'Cretaceous', 'size': 'large'},
    'Stegosaurus': {'life_expectancy': 25, 'diet': 'herbivore', 'period': 'Jurassic', 'size': 'large'},
    'Triceratops': {'life_expectancy': 35, 'diet': 'herbivore', 'period': 'Cretaceous', 'size': 'large'},
    'Velociraptor': {'life_expectancy': 20, 'diet': 'carnivore', 'period': 'Cretaceous', 'size': 'small'},
    'Brachiosaurus': {'life_expectancy': 40, 'diet': 'herbivore', 'period': 'Jurassic', 'size': 'large'},
    'Ankylosaurus': {'life_expectancy': 30, 'diet': 'herbivore', 'period': 'Cretaceous', 'size': 'medium'},
    'Allosaurus': {'life_expectancy': 28, 'diet': 'carnivore', 'period': 'Jurassic', 'size': 'large'},
    'Diplodocus': {'life_expectancy': 35, 'diet': 'herbivore', 'period': 'Jurassic', 'size': 'large'},
    'Pteranodon': {'life_expectancy': 25, 'diet': 'carnivore', 'period': 'Cretaceous', 'size': 'medium'},
    'Spinosaurus': {'life_expectancy': 32, 'diet': 'carnivore', 'period': 'Cretaceous', 'size': 'large'},
    'Parasaurolophus': {'life_expectancy': 28, 'diet': 'herbivore', 'period': 'Cretaceous', 'size': 'medium'},
    'Iguanodon': {'life_expectancy': 27, 'diet': 'herbivore', 'period': 'Cretaceous', 'size': 'medium'},
    'Brontosaurus': {'life_expectancy': 35, 'diet': 'herbivore', 'period': 'Jurassic', 'size': 'large'},
    'Carcharodontosaurus': {'life_expectancy': 30, 'diet': 'carnivore', 'period': 'Cretaceous', 'size': 'large'},
    'Archaeopteryx': {'life_expectancy': 3, 'diet': 'carnivore', 'period': 'Jurassic', 'size': 'small'},
    'Ceratosaurus': {'life_expectancy': 28, 'diet': 'carnivore', 'period': 'Jurassic', 'size': 'medium'},
    'Gallimimus': {'life_expectancy': 25, 'diet': 'herbivore', 'period': 'Cretaceous', 'size': 'medium'},
    'Therizinosaurus': {'life_expectancy': 30, 'diet': 'herbivore', 'period': 'Cretaceous', 'size': 'large'},
    'Troodon': {'life_expectancy': 20, 'diet': 'carnivore', 'period': 'Cretaceous', 'size': 'small'},
    'Dilophosaurus': {'life_expectancy': 25, 'diet': 'carnivore', 'period': 'Jurassic', 'size': 'medium'},
    'Deinonychus': {'life_expectancy': 30, 'diet': 'carnivore', 'period': 'Cretaceous', 'size': 'medium'},
    'Plateosaurus': {'life_expectancy': 30, 'diet': 'herbivore', 'period': 'Triassic', 'size': 'large'}
}

def find_dinosaurs(dinosaur_dict, life_expectancy_threshold=None, diet=None, period=None, size=None):
    filtered_dinosaurs = []
    for dino, info in dinosaur_dict.items():
        if (life_expectancy_threshold is None or info['life_expectancy'] > life_expectancy_threshold) \
                and (diet is None or info['diet'] == diet) \
                and (period is None or info['period'] == period) \
                and (size is None or info['size'] == size):
            filtered_dinosaurs.append(dino)
    return filtered_dinosaurs

# Examples with different filters
filters = [
    {'life_expectancy_threshold': 30, 'diet': 'carnivore', 'period': 'Cretaceous', 'size': 'large'},
    {'life_expectancy_threshold': 25, 'diet': 'herbivore', 'period': 'Jurassic', 'size': 'large'},
    {'diet': 'carnivore', 'period': 'Jurassic', 'size': 'small'},
    {'period': 'Cretaceous', 'size': 'medium'}
]

for filter_options in filters:
    filtered_dinosaurs = find_dinosaurs(dinosaur_info, **filter_options)
    print("Dinosaurs matching filter options:", filtered_dinosaurs)

##
##

