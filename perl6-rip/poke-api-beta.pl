#!/usr/bin/perl
##
##
###################################
###################################
##

##################################################################
# Script for upgrading PokeAPI CSV files with FTP-uploaded data. #
#                                                                #
# Usage:                                                         #
# ./csvupdate <type> <file(s)>                                   #
#                                                                #
# Arguments:                                                     #
# - type: PokeAPI CSV file type                                  #
#         (must have the correct number of fields)               #
# - file(s): list of files containing CSV data                   #
##################################################################

use strict;
use warnings;
use Text::CSV;

my $csv_dir = "/opt/pokeapi/data/v2/csv";

my %csv_fields = (
  'abilities' => 4,
  'ability_changelog' => 3,
  'ability_changelog_prose' => 3,
  'ability_flavor_text' => 4,
  'ability_names' => 3,
  'ability_prose' => 4,
  'berries' => 10,
  'berry_firmness' => 2,
  'berry_firmness_names' => 3,
  'berry_flavors' => 3,
  'characteristics' => 3,
  'characteristic_text' => 3,
  'conquest_episode_names' => 3,
  'conquest_episodes' => 2,
  'conquest_episode_warriors' => 2,
  'conquest_kingdom_names' => 3,
  'conquest_kingdoms' => 3,
  'conquest_max_links' => 3,
  'conquest_move_data' => 7,
  'conquest_move_displacement_prose' => 5,
  'conquest_move_displacements' => 3,
  'conquest_move_effect_prose' => 4,
  'conquest_move_effects' => 1,
  'conquest_move_range_prose' => 4,
  'conquest_move_ranges' => 3,
  'conquest_pokemon_abilities' => 3,
  'conquest_pokemon_evolution' => 8,
  'conquest_pokemon_moves' => 2,
  'conquest_pokemon_stats' => 3,
  'conquest_stat_names' => 3,
  'conquest_stats' => 3,
  'conquest_transformation_pokemon' => 2,
  'conquest_transformation_warriors' => 2,
  'conquest_warrior_archetypes' => 2,
  'conquest_warrior_names' => 3,
  'conquest_warrior_ranks' => 4,
  'conquest_warrior_rank_stat_map' => 3,
  'conquest_warriors' => 4,
  'conquest_warrior_skill_names' => 3,
  'conquest_warrior_skills' => 2,
  'conquest_warrior_specialties' => 3,
  'conquest_warrior_stat_names' => 3,
  'conquest_warrior_stats' => 2,
  'conquest_warrior_transformation' => 10,
  'contest_combos' => 2,
  'contest_effect_prose' => 4,
  'contest_effects' => 3,
  'contest_type_names' => 5,
  'contest_types' => 2,
  'egg_group_prose' => 3,
  'egg_groups' => 2,
  'encounter_condition_prose' => 3,
  'encounter_conditions' => 2,
  'encounter_condition_value_map' => 2,
  'encounter_condition_value_prose' => 3,
  'encounter_condition_values' => 4,
  'encounter_method_prose' => 3,
  'encounter_methods' => 3,
  'encounters' => 7,
  'encounter_slots' => 5,
  'evolution_chains' => 2,
  'evolution_trigger_prose' => 3,
  'evolution_triggers' => 2,
  'experience' => 3,
  'genders' => 2,
  'generation_names' => 3,
  'generations' => 3,
  'growth_rate_prose' => 3,
  'growth_rates' => 3,
  'item_categories' => 3,
  'item_category_prose' => 3,
  'item_flag_map' => 2,
  'item_flag_prose' => 4,
  'item_flags' => 2,
  'item_flavor_summaries' => 3,
  'item_flavor_text' => 4,
  'item_fling_effect_prose' => 3,
  'item_fling_effects' => 2,
  'item_game_indices' => 3,
  'item_names' => 3,
  'item_pocket_names' => 3,
  'item_pockets' => 2,
  'item_prose' => 4,
  'items' => 6,
  'language_names' => 3,
  'languages' => 6,
  'location_area_encounter_rates' => 4,
  'location_area_prose' => 3,
  'location_areas' => 4,
  'location_game_indices' => 3,
  'location_names' => 4,
  'locations' => 3,
  'machines' => 4,
  'move_battle_style_prose' => 3,
  'move_battle_styles' => 2,
  'move_changelog' => 10,
  'move_damage_classes' => 2,
  'move_damage_class_prose' => 4,
  'move_effect_changelog' => 3,
  'move_effect_changelog_prose' => 3,
  'move_effect_prose' => 4,
  'move_effects' => 1,
  'move_flag_map' => 2,
  'move_flag_prose' => 4,
  'move_flags' => 2,
  'move_flavor_summaries' => 3,
  'move_flavor_text' => 4,
  'move_meta_ailment_names' => 3,
  'move_meta_ailments' => 2,
  'move_meta_categories' => 2,
  'move_meta_category_prose' => 3,
  'move_meta' => 13,
  'move_meta_stat_changes' => 3,
  'move_names' => 3,
  'moves' => 15,
  'move_target_prose' => 4,
  'move_targets' => 2,
  'nature_battle_style_preferences' => 4,
  'nature_names' => 3,
  'nature_pokeathlon_stats' => 3,
  'natures' => 7,
  'pal_park_area_names' => 3,
  'pal_park_areas' => 2,
  'pal_park' => 4,
  'pokeathlon_stat_names' => 3,
  'pokeathlon_stats' => 2,
  'pokedexes' => 4,
  'pokedex_prose' => 4,
  'pokedex_version_groups' => 2,
  'pokemon_abilities' => 4,
  'pokemon_color_names' => 3,
  'pokemon_colors' => 2,
  'pokemon' => 8,
  'pokemon_dex_numbers' => 3,
  'pokemon_egg_groups' => 2,
  'pokemon_evolution' => 20,
  'pokemon_form_generations' => 3,
  'pokemon_form_names' => 4,
  'pokemon_form_pokeathlon_stats' => 5,
  'pokemon_forms' => 10,
  'pokemon_form_types' => 3,
  'pokemon_game_indices' => 3,
  'pokemon_habitat_names' => 3,
  'pokemon_habitats' => 2,
  'pokemon_items' => 4,
  'pokemon_move_method_prose' => 4,
  'pokemon_move_methods' => 2,
  'pokemon_moves' => 6,
  'pokemon_shape_prose' => 5,
  'pokemon_shapes' => 2,
  'pokemon_species' => 20,
  'pokemon_species_flavor_summaries' => 3,
  'pokemon_species_flavor_text' => 4,
  'pokemon_species_names' => 4,
  'pokemon_species_prose' => 3,
  'pokemon_stats' => 4,
  'pokemon_types' => 3,
  'pokemon_types_past' => 4,
  'region_names' => 3,
  'regions' => 2,
  'stat_names' => 3,
  'stats' => 5,
  'super_contest_combos' => 2,
  'super_contest_effect_prose' => 3,
  'super_contest_effects' => 2,
  'type_efficacy' => 3,
  'type_game_indices' => 3,
  'type_names' => 3,
  'types' => 4,
  'version_group_pokemon_move_methods' => 2,
  'version_group_regions' => 2,
  'version_groups' => 4,
  'version_names' => 3,
  'versions' => 3
);


if($#ARGV < 1)
{
  die "Usage: $0 <type> <file(s)>\n";
}

my $type = $ARGV[0];
if(!exists $csv_fields{$type})
{
  die "Unrecognised CSV data type: $type.\n";
}

my $csv = Text::CSV->new({ sep_char => ',' });

my $fname = "${csv_dir}/${type}.csv";
open(my $fh, ">>", $fname) or die "Unable to open CSV target file.\n";

shift;
for(<>)
{
  chomp;
  if($csv->parse($_))
  {
    my @fields = $csv->fields();
    if(@fields != $csv_fields{$type})
    {
      warn "Incorrect number of fields: '$_'\n";
      next;
    }
    print $fh "$_\n";
  }
}

close($fh);

##
##
#####################################
##
