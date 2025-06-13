"""Component system module -  Components instead of chaotic class hierarchy mess."""

# Programmed by CoolCat467

from __future__ import annotations

# Copyright (C) 2023-2024  CoolCat467
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.

__title__ = "Component"
__author__ = "CoolCat467"
__license__ = "GNU General Public License Version 3"
__version__ = "0.0.5"

import sys
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Generic, TypeVar
from weakref import ref

import trio

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator, Iterable

    from mypy_extensions import u8

T = TypeVar("T")


class Event(Generic[T]):
    """Event with name, data, and re-raise levels."""

    __slots__ = ("data", "level", "name")

    def __init__(
        self,
        name: str,
        data: T,
        levels: u8 = 0,
    ) -> None:
        """Initialize event."""
        self.name = name
        self.data = data
        self.level = levels

    def __repr__(self) -> str:
        """Return representation of self."""
        return f"{self.__class__.__name__}({self.name!r}, {self.data!r}, {self.level!r})"

    def pop_level(self) -> bool:
        """Travel up one level and return True if event should continue or not."""
        continue_level = self.level > 0
        self.level = max(0, self.level - 1)
        return continue_level


class Component:
    """Component base class."""

    __slots__ = ("__manager", "name")

    def __init__(self, name: object) -> None:
        """Initialise with name."""
        self.name = name
        self.__manager: ref[ComponentManager] | None = None

    def __repr__(self) -> str:
        """Return representation of self."""
        return f"{self.__class__.__name__}({self.name!r})"

    @property
    def manager(self) -> ComponentManager:
        """ComponentManager if bound to one, otherwise raise AttributeError."""
        if self.__manager is not None:
            manager = self.__manager()
            if manager is not None:
                return manager
        raise AttributeError(f"No component manager bound for {self.name}")

    def _unbind(self) -> None:
        """If you use this you are evil. This is only for ComponentManagers!."""
        self.__manager = None

    @property
    def manager_exists(self) -> bool:
        """Return if manager is bound or not."""
        return self.__manager is not None and self.__manager() is not None

    def register_handler(
        self,
        event_name: str,
        handler_coro: Callable[[Event[Any]], Awaitable[Any]],
    ) -> None:
        """Register handler with bound component manager.

        Raises AttributeError if this component is not bound.
        """
        self.manager.register_component_handler(
            event_name,
            handler_coro,
            self.name,
        )

    def register_handlers(
        self,
        handlers: dict[str, Callable[[Event[Any]], Awaitable[Any]]],
    ) -> None:
        """Register multiple handler Coroutines.

        Raises AttributeError if this component is not bound.
        """
        for name, coro in handlers.items():
            self.register_handler(name, coro)

    def bind_handlers(self) -> None:
        """Add handlers in subclass."""

    def bind(self, manager: ComponentManager) -> None:
        """Bind self to manager.

        Raises RuntimeError if component is already bound to a manager.
        """
        if self.manager_exists:
            raise RuntimeError(
                f"{self.name} component is already bound to {self.manager}",
            )
        self.__manager = ref(manager)
        self.bind_handlers()

    def has_handler(self, event_name: str) -> bool:
        """Return if manager has event handlers registered for a given event.

        Raises AttributeError if this component is not bound.
        """
        return self.manager.has_handler(event_name)

    def unregister_handler(
        self,
        event_name: str,
        handler_coro: Callable[[Event[Any]], Awaitable[None]],
    ) -> None:
        """Unregister a handler function for event_name.

        Raises AttributeError if this component is not bound.
        Raises ValueError if no component with given name is registered.
        """
        return self.manager.unregister_component_handler(
            event_name,
            handler_coro,
            self.name,
        )

    def unregister_handler_type(self, event_name: str) -> None:
        """Unregister all event handlers for a given event type.

        Raises AttributeError if this component is not bound.
        """
        self.manager.unregister_handler_type(event_name)

    async def raise_event(self, event: Event[Any]) -> None:
        """Raise event for bound manager.

        Raises AttributeError if this component is not bound.
        """
        try:
            await self.manager.raise_event(event)
        except Exception as exc:
            if sys.version_info >= (3, 11):  # pragma: nocover
                exc.add_note(f"{event = }")
            raise

    def component_exists(self, component_name: str) -> bool:
        """Return if component exists in manager.

        Raises AttributeError if this component is not bound.
        """
        return self.manager.component_exists(component_name)

    def components_exist(self, component_names: Iterable[str]) -> bool:
        """Return if all component names given exist in manager.

        Raises AttributeError if this component is not bound.
        """
        return self.manager.components_exist(component_names)

    def get_component(self, component_name: str) -> Any:
        """Get Component from manager.

        Raises AttributeError if this component is not bound.
        """
        return self.manager.get_component(component_name)

    def get_components(
        self,
        component_names: Iterable[str],
    ) -> list[Component]:
        """Return Components from manager.

        Raises AttributeError if this component is not bound.
        """
        return self.manager.get_components(component_names)


ComponentPassthrough = TypeVar("ComponentPassthrough", bound=Component)


class ComponentManager(Component):
    """Component manager class."""

    __slots__ = ("__components", "__event_handlers", "__weakref__")

    def __init__(self, name: object, own_name: object | None = None) -> None:
        """If own_name is set, add self to list of components as specified name."""
        super().__init__(name)
        self.__event_handlers: dict[
            str,
            set[tuple[Callable[[Event[Any]], Awaitable[Any]], object]],
        ] = {}
        self.__components: dict[object, Component] = {}

        if own_name is not None:
            self.__add_self_as_component(own_name)
        self.bind_handlers()

    def __repr__(self) -> str:
        """Return representation of self."""
        return f"<{self.__class__.__name__} Components: {self.__components}>"

    def __add_self_as_component(self, name: object) -> None:
        """Add this manager as component to self without binding.

        Raises ValueError if a component with given name already exists.
        """
        if self.component_exists(name):  # pragma: nocover
            raise ValueError(f'Component named "{name}" already exists!')
        self.__components[name] = self

    def register_handler(
        self,
        event_name: str,
        handler_coro: Callable[[Event[Any]], Awaitable[None]],
    ) -> None:
        """Register handler_func as handler for event_name (self component)."""
        self.register_component_handler(event_name, handler_coro, self.name)

    def register_component_handler(
        self,
        event_name: str,
        handler_coro: Callable[[Event[Any]], Awaitable[None]],
        component_name: object,
    ) -> None:
        """Register handler_func as handler for event_name.

        Raises ValueError if no component with given name is registered.
        """
        if (
            component_name != self.name
            and component_name not in self.__components
        ):
            raise ValueError(
                f"Component named {component_name!r} is not registered!",
            )
        if event_name not in self.__event_handlers:
            self.__event_handlers[event_name] = set()
        self.__event_handlers[event_name].add((handler_coro, component_name))

    def unregister_component_handler(
        self,
        event_name: str,
        handler_coro: Callable[[Event[Any]], Awaitable[None]],
        component_name: object,
    ) -> None:
        """Unregister a handler function for event_name for a given component.

        Raises ValueError if no component with given name is registered.
        """
        if (
            component_name != self.name
            and component_name not in self.__components
        ):
            raise ValueError(
                f"Component named {component_name!r} is not registered!",
            )

        if event_name not in self.__event_handlers:
            return

        handler_tuple = (handler_coro, component_name)
        if handler_tuple in self.__event_handlers[event_name]:
            self.__event_handlers[event_name].remove(handler_tuple)

        # If the event_name no longer has any handlers, remove it
        if not self.__event_handlers[event_name]:
            del self.__event_handlers[event_name]

    def unregister_handler(
        self,
        event_name: str,
        handler_coro: Callable[[Event[Any]], Awaitable[None]],
    ) -> None:
        """Unregister a handler function for event_name.

        Raises ValueError if no component with given name is registered.
        """
        self.unregister_component_handler(event_name, handler_coro, self.name)

    def unregister_handler_type(
        self,
        event_name: str,
    ) -> None:
        """Unregister all event handlers for a given event type."""
        if event_name in self.__event_handlers:
            del self.__event_handlers[event_name]

    def has_handler(self, event_name: str) -> bool:
        """Return if there are event handlers registered for a given event."""
        return bool(self.__event_handlers.get(event_name))

    async def raise_event_in_nursery(
        self,
        event: Event[Any],
        nursery: trio.Nursery,
    ) -> None:
        """Raise event in a particular trio nursery.

        Could raise RuntimeError if given nursery is no longer open.
        """
        await trio.lowlevel.checkpoint()

        # Forward leveled events up; They'll come back to us soon enough.
        if self.manager_exists and event.pop_level():
            await super().raise_event(event)
            # nursery.start_soon(super().raise_event, event)
            return
        # Make sure events not raised twice
        # if not self.manager_exists:
        # while event.level > 0:
        # event.pop_level()

        # if not event.name.startswith("Pygame") and event.name not in {"tick", "gameboard_create_piece", "server->create_piece", "create_piece->network"}:
        # print(f'''{self.__class__.__name__}({self.name!r}):\n{event = }''')

        # Call all registered handlers for this event
        if event.name in self.__event_handlers:
            for handler, _name in self.__event_handlers[event.name]:
                nursery.start_soon(handler, event)

        # Forward events to contained managers
        for component in self.get_all_components():
            # Skip self component if exists
            if component is self:
                continue
            if isinstance(component, ComponentManager):
                nursery.start_soon(component.raise_event, event)

    async def raise_event(self, event: Event[Any]) -> None:
        """Raise event for all components that have handlers registered."""
        async with trio.open_nursery() as nursery:
            await self.raise_event_in_nursery(event, nursery)

    def add_component(self, component: Component) -> None:
        """Add component to this manager.

        Raises ValueError if component already exists with component name.
        `component` must be an instance of Component.
        """
        assert isinstance(component, Component), "Must be component instance"
        if self.component_exists(component.name):
            raise ValueError(
                f'Component named "{component.name}" already exists!',
            )
        self.__components[component.name] = component
        component.bind(self)

    def add_components(self, components: Iterable[Component]) -> None:
        """Add multiple components to this manager.

        Raises ValueError if any component already exists with component name.
        `component`s must be instances of Component.
        """
        for component in components:
            self.add_component(component)

    def remove_component(self, component_name: object) -> None:
        """Remove a component.

        Raises ValueError if component name does not exist.
        """
        if not self.component_exists(component_name):
            raise ValueError(f"Component {component_name!r} does not exist!")
        # Remove component from registered components
        component = self.__components.pop(component_name)
        # Tell component they need to unbind
        component._unbind()

        # Unregister component's event handlers
        # List of events that will have no handlers once we are done
        empty = []
        for event_name, handlers in self.__event_handlers.items():
            for item in tuple(handlers):
                _handler, handler_component = item
                if handler_component == component_name:
                    self.__event_handlers[event_name].remove(item)
                    if not self.__event_handlers[event_name]:
                        empty.append(event_name)
        # Remove event handler table keys that have no items anymore
        for name in empty:
            self.__event_handlers.pop(name)

    def component_exists(self, component_name: object) -> bool:
        """Return if component exists in this manager."""
        return component_name in self.__components

    @contextmanager
    def temporary_component(
        self,
        component: ComponentPassthrough,
    ) -> Generator[ComponentPassthrough, None, None]:
        """Temporarily add given component but then remove after exit."""
        name = component.name
        self.add_component(component)
        try:
            yield component
        finally:
            if self.component_exists(name):
                self.remove_component(name)

    def components_exist(self, component_names: Iterable[object]) -> bool:
        """Return if all component names given exist in this manager."""
        return all(self.component_exists(name) for name in component_names)

    def get_component(self, component_name: object) -> Any:
        """Return Component or raise ValueError because it doesn't exist."""
        if not self.component_exists(component_name):
            raise ValueError(f'"{component_name}" component does not exist')
        return self.__components[component_name]

    def get_components(self, component_names: Iterable[object]) -> list[Any]:
        """Return iterable of components asked for or raise ValueError."""
        return [self.get_component(name) for name in component_names]

    def list_components(self) -> tuple[object, ...]:
        """Return tuple of the names of components bound to this manager."""
        return tuple(self.__components)

    def get_all_components(self) -> tuple[Component, ...]:
        """Return tuple of all components bound to this manager."""
        return tuple(self.__components.values())

    def unbind_components(self) -> None:
        """Unbind all components, allows things to get garbage collected."""
        self.__event_handlers.clear()
        for component in iter(self.__components.values()):
            if (
                isinstance(component, ComponentManager)
                and component is not self
            ):
                component.unbind_components()
            component._unbind()
        self.__components.clear()

    def __del__(self) -> None:
        """Unbind components."""
        self.unbind_components()


class ExternalRaiseManager(ComponentManager):
    """Component Manager, but raises events in an external nursery."""

    __slots__ = ("nursery",)

    def __init__(
        self,
        name: object,
        nursery: trio.Nursery,
        own_name: object | None = None,
    ) -> None:
        """Initialize with name, own component name, and nursery."""
        super().__init__(name, own_name)
        self.nursery = nursery

    async def raise_event(self, event: Event[Any]) -> None:
        """Raise event in nursery.

        Could raise RuntimeError if self.nursery is no longer open.
        """
        # if not event.name.startswith("Pygame") and event.name not in {"tick"}:
        #    print(f'[libcomponent.component.ExternalRaiseManager] {event = }')
        await self.raise_event_in_nursery(event, self.nursery)

    async def raise_event_internal(self, event: Event[Any]) -> None:
        """Raise event in internal nursery."""
        await super().raise_event(event)


if __name__ == "__main__":  # pragma: nocover
    print(f"{__title__}\nProgrammed by {__author__}.")
