#!/usr/bin/env python3
"""Generate data/wordlist.txt: a 5,000-entry password dictionary.

Structure:
  - ~5000 unique words built from common password roots x suffix patterns
    (bare, digits 0-9, years 2000-2026).
  - "shadow99"   placed at line 4950
  - "dragon2026" placed at line 4951
    (i.e. both near the END of the file, forcing a near-full dictionary scan).
"""

import os

ROOTS = [
    "apple", "amber", "angle", "anchor", "arrow", "aurora", "autumn", "aztec",
    "bacon", "badger", "bagel", "baker", "bamboo", "banana", "bandit", "banjo",
    "barn", "basil", "basket", "batch", "beacon", "bean", "beard", "beaver",
    "beetle", "bell", "berry", "bishop", "bison", "blade", "blanket", "blaze",
    "blend", "blink", "block", "blossom", "blue", "board", "bolt", "bonus",
    "book", "boot", "border", "bottle", "boulder", "bounce", "brave", "bread",
    "brick", "bridge", "bright", "bronze", "brook", "brush", "bubble", "bucket",
    "buffalo", "bugle", "builder", "bulb", "bundle", "bunny", "burger", "burrow",
    "butter", "button", "cabin", "cable", "cactus", "camel", "camera", "camp",
    "canal", "candle", "canoe", "canyon", "cargo", "carpet", "carrot", "castle",
    "catalog", "cedar", "cellar", "cement", "chain", "chalk", "champion", "charm",
    "cheese", "cherry", "chess", "chief", "chili", "chimney", "chip", "chisel",
    "cider", "cinema", "circle", "citrus", "city", "clamp", "claw", "clay",
    "cliff", "climb", "clock", "cloud", "clover", "coach", "coast", "cobalt",
    "cobra", "cocoa", "coffee", "coin", "comet", "compass", "cookie", "copper",
    "coral", "cork", "corn", "cosmos", "cotton", "county", "couple", "courage",
    "crater", "crayon", "cream", "cricket", "crisp", "crown", "crumb", "crystal",
    "cube", "cuckoo", "cup", "curve", "cyborg", "cycle", "daisy", "dancer",
    "dandy", "dawn", "delta", "denim", "desert", "diamond", "dice", "diesel",
    "dime", "dinner", "dino", "dish", "diver", "dock", "dolphin", "domino",
    "donkey", "donut", "doodle", "door", "dorito", "dot", "dove", "dragon",
    "drift", "drill", "drum", "duck", "dune", "dusk", "eagle", "earth",
    "easel", "echo", "eclair", "eclipse", "edge", "editor", "eel", "egg",
    "elbow", "elder", "elephant", "ember", "emerald", "engine", "enigma", "entry",
    "envelope", "epoch", "eraser", "error", "escort", "essay", "estate", "ethics",
    "evening", "event", "fable", "fabric", "falcon", "family", "fancy", "farm",
    "feather", "fence", "fern", "ferry", "fiber", "fiddle", "field", "fig",
    "filter", "finch", "finger", "fire", "fish", "fist", "flag", "flame",
    "flamingo", "flank", "flash", "fleet", "flint", "float", "flock", "flora",
    "flower", "flute", "foam", "fog", "forest", "fork", "fort", "fossil",
    "fountain", "fox", "frame", "freedom", "frost", "fruit", "fudge", "fungus",
    "funnel", "furnace", "fuzzy", "galaxy", "galleon", "garden", "garlic", "gauge",
    "gavel", "gazelle", "gecko", "geyser", "ginger", "giraffe", "glacier", "glass",
    "glide", "globe", "glove", "glow", "glue", "gnome", "goat", "goblet",
    "gold", "goose", "gopher", "gorge", "grape", "graph", "grass", "gravel",
    "gravy", "green", "grid", "griffin", "grill", "groove", "guitar", "gulf",
    "gum", "gusto", "gutter", "hair", "hall", "hamlet", "hammer",
    "hamster", "handle", "harbor", "harmony", "harvest", "hawk", "hazel", "heart",
    "heather", "hedge", "helium", "helmet", "heron", "hexagon", "hickory", "hill",
    "hinge", "hobby", "hockey", "holly", "honey", "hood", "hoof", "hook",
    "hop", "horizon", "hornet", "horse", "hostel", "hotel", "hour", "house",
    "hover", "huckleberry", "hudson", "human", "humble", "hurdle", "hut", "hydro",
    "iceberg", "icon", "igloo", "impact", "index", "indigo", "ingot", "inlet",
    "insect", "iron", "island", "ivory", "jacket", "jade", "jaguar", "jasmine",
    "jelly", "jet", "jewel", "jockey", "jolly", "jordan", "jubilee", "judge",
    "juggle", "juice", "jumbo", "jungle", "juniper", "kayak", "kelp", "kennel",
    "kernel", "kettle", "keyboard", "kidney", "kilt", "kimono", "kindle", "king",
    "kiosk", "kitten", "knight", "knot", "koala", "label", "ladder", "lagoon",
    "lantern", "laptop", "laser", "lasso", "latch", "laurel", "lava", "lavender",
    "leaf", "ledger", "legend", "lemon", "lens", "leopard", "lever", "liberty",
    "licorice", "lily", "limb", "lime", "liner", "lint", "lion", "liquid",
    "lizard", "llama", "lobby", "lobster", "locket", "locomotive", "loft", "logic",
    "loop", "lotus", "lumber", "lunar", "lynx", "lyric", "macaw", "magnet",
    "mahogany", "maize", "mallet", "mammoth", "mango", "mantis", "maple", "marble",
    "march", "margin", "marine", "market", "marmot", "mars", "mascot", "mask",
    "mason", "matrix", "mayor", "meadow", "medal", "melon", "memo", "mentor",
    "mercury", "mermaid", "meteor", "metro", "midland", "midway", "mimic", "mineral",
    "mingle", "mint", "mirror", "mist", "mite", "moat", "mobile", "mocker",
    "module", "mohair", "molar", "monarch", "monday", "monsoon", "moral", "morning",
    "mosaic", "mosquito", "moss", "motel", "motion", "motor", "mound", "mountain",
    "mouse", "movie", "muffin", "mug", "mule", "mural", "muse", "mushroom",
    "music", "mustard", "myrtle", "mystery", "nachos", "napkin", "narrow", "nation",
    "native", "nature", "nebula", "nectar", "needle", "neighbor", "neon", "nest",
    "nettle", "network", "nickel", "nimble", "ninja", "noble", "nomad", "noodle",
    "north", "nose", "notch", "notebook", "novel", "nugget", "number", "nurse",
    "nutmeg", "oasis", "oat", "obelisk", "ocean", "octagon", "octave", "octopus",
    "office", "olive", "onyx", "opal", "opera", "optic", "orange", "orbit",
    "orchard", "orchid", "organ", "origin", "osprey", "ostrich", "otter", "ounce",
    "outpost", "oval", "oven", "owl", "oxide", "oyster", "ozone", "paddle",
    "pagoda", "painter", "palace", "pallet", "palm", "pancake", "panda", "panel",
    "panther", "papaya", "paper", "parade", "parcel", "pardon", "parka", "parlor",
    "parrot", "parsley", "pastel", "pastry", "patch", "path", "patio", "patrol",
    "pattern", "pavement", "paw", "payment", "peach", "peacock", "peak", "peanut",
    "pear", "pebble", "pelican", "pencil", "penguin", "pepper", "perfume", "petal",
    "pewter", "phantom", "phone", "photo", "piano", "piccolo", "pickle", "picnic",
    "pigeon", "pilgrim", "pillow", "pilot", "pin", "pine", "pint", "pioneer",
    "pipeline", "pistol", "pitch", "pivot", "pixel", "pizza", "plank", "plasma",
    "plate", "platinum", "player", "pledge", "plank", "plum", "plunder", "pocket",
    "podium", "point", "polar", "polish", "pollen", "pomelo", "poncho", "pony",
    "poplar", "poppy", "popsicle", "portal", "poster", "potato", "pottery", "pouch",
    "powder", "power", "prairie", "pretzel", "prism", "prize", "profile", "prompt",
    "prong", "proof", "prop", "prose", "proud", "proven", "prune", "puddle",
    "puffin", "pumpkin", "punch", "puppet", "puzzle", "pyramid", "quail", "quarry",
    "quartz", "queen", "quest", "quicksand", "quiet", "quill", "quilt", "quince",
    "quiver", "quota", "rabbit", "racer", "radar", "radio", "radish", "raft",
    "rail", "rainbow", "raisin", "rally", "ramble", "ranch", "random", "ranger",
    "raven", "ravine", "razor", "reactor", "reader", "realm", "rebel", "record",
    "reef", "reflect", "regal", "region", "relic", "remedy", "render", "report",
    "reptile", "rescue", "resort", "retro", "reveal", "ribbon", "riddle", "rifle",
    "ring", "riot", "ripple", "riser", "river", "road", "roast", "robe",
    "rocket", "rodeo", "rogue", "roller", "roman", "rooster", "root", "rope",
    "rose", "rotor", "rouge", "round", "router", "royal", "rubber", "ruby",
    "rudder", "rugby", "ruler", "rumor", "runner", "runway", "rural", "rust",
    "saddle", "safari", "sail", "salad", "salmon", "saloon", "salsa", "salt",
    "sample", "sandal", "sapphire", "sardine", "satchel", "satin", "sauce", "sauna",
    "savanna", "scale", "scanner", "scarf", "scatter", "scene", "scent", "school",
    "scoop", "scooter", "scout", "scrap", "screen", "screw", "script", "scroll",
    "sculpt", "season", "second", "sector", "sedan", "seed", "segment", "seldom",
    "senate", "senator", "sensor", "sequel", "serial", "sermon", "serpent", "servo",
    "seven", "shadow", "shallow", "shampoo", "shark", "shave", "sheep", "sheet",
    "shelf", "shell", "sheriff", "shield", "shift", "ship", "shirt", "shiver",
    "shoe", "shore", "short", "shout", "shovel", "show", "shrimp", "shrine",
    "shuffle", "shutter", "sibling", "sierra", "sigma", "signal", "silence", "silicon",
    "silk", "silver", "similar", "simple", "siren", "sister", "six", "sketch",
    "skier", "skill", "skirt", "sky", "slalom", "sleeve", "slim", "slipper",
    "slogan", "slope", "smile", "smoke", "snack", "snail", "snake", "snap",
    "snapshot", "snout", "snow", "sock", "soda", "sofa", "soft", "soil",
    "solar", "soldier", "solid", "sonar", "sonnet", "soprano", "sorbet", "sound",
    "soup", "source", "south", "soy", "space", "spade", "spangle", "spark",
    "sparrow", "spatial", "speaker", "spear", "special", "specimen", "spectra", "sphere",
    "spice", "spider", "spike", "spindle", "spiral", "spirit", "splash", "sponge",
    "spool", "spoon", "sport", "spot", "spout", "spray", "spring", "sprout",
    "spruce", "spur", "spyglass", "square", "squash", "squid", "stable", "stack",
    "stadium", "staff", "stage", "stain", "stair", "stamp", "stand", "staple",
    "starch", "starling", "station", "statue", "status", "steak", "steam", "steel",
    "stellar", "stencil", "stereo", "sterling", "stew", "stick", "sting", "stitch",
    "stock", "stone", "stool", "stopwatch", "store", "stork", "storm", "stove",
    "strand", "stream", "street", "stride", "strike", "string", "stripe", "stroll",
    "structure", "studio", "study", "stumble", "stump", "stunt", "style", "subject",
    "subway", "sugar", "suggest", "suit", "sulfur", "summer", "summit", "sunday",
    "sunset", "superb", "supply", "support", "surface", "surge", "surplus", "surrey",
    "survey", "swallow", "swamp", "swan", "swatch", "sweater", "swift", "switch",
    "sword", "sycamore", "symbol", "symptom", "syrup", "system", "table", "tablet",
    "tackle", "taco", "tact", "tailor", "talent", "tandem", "tangent", "tanker",
    "tapestry", "tapioca", "tariff", "tavern", "taxi", "teacher", "teapot", "techno",
    "tempest", "temple", "tenant", "tennis", "tent", "tepid", "terrace", "terrain",
    "textile", "texture", "thanks", "theater", "theme", "theory", "thermos", "thicket",
    "thimble", "thistle", "thorn", "thread", "thrill", "throne", "thumb", "thunder",
    "ticket", "tidal", "tiger", "timber", "timid", "tinsel", "titan", "toast",
    "tobacco", "toffee", "toggle", "token", "tomato", "tonic", "tool", "topaz",
    "topper", "torch", "tornado", "torrent", "total", "toucan", "touch", "tour",
    "towel", "tower", "trace", "track", "trailer", "train", "tram", "transfer",
    "trapeze", "travel", "tray", "treasure", "treat", "tree", "tremble", "trench",
    "trend", "trial", "tribe", "trick", "trident", "trio", "trip", "triumph",
    "trolley", "trophy", "tropic", "trout", "truck", "truffle", "trumpet", "trunk",
    "trust", "truth", "tulip", "tumble", "tundra", "tunnel", "turbine", "turkey",
    "turnip", "turtle", "tusk", "tutor", "tweed", "twilight", "twine", "twist",
    "typewriter", "udder", "ultra", "umbrella", "unable", "uncle", "under", "unfold",
    "uniform", "union", "unique", "unit", "unite", "unity", "universe", "unlock",
    "until", "unusual", "upbeat", "upgrade", "upload", "upright", "upset", "upstream",
    "urban", "urchin", "urgent", "usable", "useful", "utensil", "utility", "utter",
    "vacuum", "valid", "valley", "value", "valve", "vanilla", "vapor", "vault",
    "vector", "velvet", "vendor", "venture", "venue", "verb", "verdict", "verify",
    "vermont", "verses", "vertex", "vessel", "veteran", "viable", "vibrant", "victory",
    "video", "viewer", "vigor", "viking", "village", "vine", "vinyl", "violet",
    "violin", "virtue", "vision", "visit", "visual", "vital", "vivid", "vocal",
    "voltage", "volume", "voyage", "waffle", "wagon", "walnut", "walrus", "wander",
    "warden", "warmth", "warrior", "wash", "wasp", "watch", "water", "wattle",
    "waver", "wax", "wealth", "weapon", "weasel", "weather", "weaver", "wedge",
    "weekly", "weight", "welcome", "weld", "well", "west", "whale", "wheat",
    "wheel", "whisker", "whisper", "whistle", "white", "widget", "width", "wild",
    "willow", "wind", "window", "winner", "winter", "wire", "wisdom", "wisp",
    "wizard", "wolf", "wombat", "wonder", "wood", "wool", "word", "work",
    "world", "worthy", "wren", "wrench", "wrinkle", "wrist", "writer", "xylophone",
    "yacht", "yak", "yam", "yard", "yarn", "year", "yeast", "yellow",
    "yodel", "yogurt", "young", "yucca", "zebra", "zenith", "zephyr", "zeppelin",
    "zigzag", "zipper", "zircon", "zodiac", "zombie", "zone", "zoo",
]

SUFFIXES = [""] + [str(d) for d in range(10)] + [str(y) for y in range(2000, 2027)]

def build_wordlist():
    words = []
    for root in ROOTS:
        for suf in SUFFIXES:
            words.append(root + suf)
    # keep only unique entries, preserving order
    seen = set()
    uniq = []
    for w in words:
        if w not in seen:
            seen.add(w)
            uniq.append(w)
    return uniq

def main():
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "wordlist.txt")
    out_path = os.path.normpath(out_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    words = build_wordlist()
    assert len(words) >= 4998, f"not enough unique words generated: {len(words)}"

    words = words[:4998]

    # Place the two special targets near line 4950 (1-based) of the 5,000-line file.
    # After insertion the file has exactly 5000 lines:
    #   line 4950 -> shadow99
    #   line 4951 -> dragon2026
    words.insert(4949, "shadow99")
    words.insert(4950, "dragon2026")
    assert len(words) == 5000, f"expected 5000 entries, got {len(words)}"

    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(words) + "\n")

    total = sum(1 for _ in open(out_path, encoding="utf-8"))
    print(f"[wordlist] wrote {total} entries -> {out_path}")
    # verify placement
    with open(out_path, encoding="utf-8") as f:
        lines = [l.rstrip("\n") for l in f]
    assert lines[4949] == "shadow99",    f"line 4950 is {lines[4949]!r}"
    assert lines[4950] == "dragon2026",  f"line 4951 is {lines[4950]!r}"
    assert len(set(lines)) == 5000, "duplicate entries detected"
    print("[wordlist] verified: line 4950 = 'shadow99', line 4951 = 'dragon2026', all 5000 unique")

if __name__ == "__main__":
    main()
