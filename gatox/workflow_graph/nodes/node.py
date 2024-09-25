class Node:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f"{self.__class__.__name__}('{self.name}')"

    def __hash__(self):
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def get_attrs(self):
        """ """
        return {
            self.__class__.__name__: True
        } 