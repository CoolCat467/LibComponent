from __future__ import annotations

import gc

import pytest
import trio

from libcomponent.component import (
    Component,
    ComponentManager,
    Event,
    ExternalRaiseManager,
)


def test_event_init() -> None:
    event = Event("event_name", {"fish": 27}, 3)
    assert event.name == "event_name"
    assert event.data == {"fish": 27}
    assert event.level == 3


def test_event_pop_level() -> None:
    event = Event("event_name", None, 3)
    assert event.pop_level()
    assert event.level == 2
    assert event.pop_level()
    assert event.level == 1
    assert event.pop_level()
    assert event.level == 0

    assert not event.pop_level()
    assert event.level == 0


def test_event_repr() -> None:
    assert repr(Event("cat_moved", (3, 3))) == "Event('cat_moved', (3, 3), 0)"


def test_component_init() -> None:
    component = Component("component_name")
    assert component.name == "component_name"


def test_component_repr() -> None:
    assert repr(Component("fish")) == "Component('fish')"


def test_component_manager_property_error() -> None:
    component = Component("waffle")
    assert not component.manager_exists
    with pytest.raises(
        AttributeError,
        match="^No component manager bound for",
    ):
        component.manager  # noqa: B018


def test_componentmanager_add_has_manager_property() -> None:
    manager = ComponentManager("manager")
    sound_effect = Component("sound_effect")
    with pytest.raises(AttributeError):
        print(sound_effect.manager)
    manager.add_component(sound_effect)
    assert manager.component_exists("sound_effect")
    assert sound_effect.manager_exists
    assert sound_effect.manager is manager
    assert sound_effect.component_exists("sound_effect")
    assert sound_effect.components_exist(("sound_effect",))
    assert not sound_effect.components_exist(("sound_effect", "waffle"))
    assert manager.list_components() == ("sound_effect",)
    assert sound_effect.get_component("sound_effect") is sound_effect
    assert sound_effect.get_components(("sound_effect",)) == [sound_effect]


def test_componentmanager_manager_property_weakref_failure() -> None:
    # Have to override __del__, unbind_components called and unbinds
    # components so weakref failure branch never hit in normal
    # circumstances
    class EvilNoUnbindManager(ComponentManager):
        def __del__(self) -> None:
            return

    manager = EvilNoUnbindManager("manager")
    sound_effect = Component("sound_effect")
    with pytest.raises(AttributeError):
        print(sound_effect.manager)
    manager.add_component(sound_effect)
    assert sound_effect.manager is manager
    del manager
    # make sure gc collects manager
    for _ in range(3):
        gc.collect()
    with pytest.raises(AttributeError):
        print(sound_effect.manager)


def test_double_bind_error() -> None:
    manager = ComponentManager("manager")
    sound_effect = Component("sound_effect")
    manager.add_component(sound_effect)
    manager_two = ComponentManager("manager_two")
    with pytest.raises(RuntimeError, match="component is already bound to"):
        manager_two.add_component(sound_effect)


def test_self_component() -> None:
    manager = ComponentManager("manager", "cat_event")
    assert manager.component_exists("cat_event")
    assert manager.get_component("cat_event") is manager

    cat_event = Component("cat_event")
    with pytest.raises(ValueError, match="already exists"):
        manager.add_component(cat_event)


def test_add_multiple() -> None:
    manager = ComponentManager("manager")
    manager.add_components(
        (
            Component("fish"),
            Component("waffle"),
        ),
    )
    assert manager.component_exists("fish")
    assert manager.component_exists("waffle")

    manager.unbind_components()
    assert not manager.get_all_components()


def test_component_not_exist_error() -> None:
    manager = ComponentManager("manager")
    with pytest.raises(ValueError, match="does not exist"):
        manager.remove_component("darkness")
    with pytest.raises(ValueError, match="does not exist"):
        manager.get_component("darkness")


@pytest.mark.trio
async def test_self_component_handler() -> None:
    event_called = False

    async def event_call(event: Event[None]) -> None:
        nonlocal event_called
        assert event.name == "fish_appears_event"
        event_called = True

    manager = ComponentManager("manager", "cat")
    manager.register_handler("fish_appears_event", event_call)

    assert manager.has_handler("fish_appears_event")

    await manager.raise_event(Event("fish_appears_event", None))
    assert event_called


@pytest.mark.trio
async def test_raise_event_register_handlers_double_call() -> None:
    event_called_count = 0

    async def event_call(event: Event[int]) -> None:
        nonlocal event_called_count
        assert event.data == 27
        event_called_count += 1

    manager = ComponentManager("manager")
    assert not manager.has_handler("event_name")

    manager.register_component_handler("event_name", event_call, manager.name)
    assert manager.has_handler("event_name")
    await manager.raise_event(Event("event_name", 27))
    assert event_called_count == 1

    event_called_count = 0

    with pytest.raises(ValueError, match="is not registered!"):
        manager.register_component_handler(
            "event_name",
            event_call,
            "2nd name",
        )
    manager.add_component(Component("2nd name"))
    manager.register_component_handler("event_name", event_call, "2nd name")

    await manager.raise_event(Event("event_name", 27))
    assert event_called_count == 2


@pytest.mark.trio
async def test_raise_event_register_handlers() -> None:
    event_called = False

    async def event_call(event: Event[int]) -> None:
        nonlocal event_called
        assert event.data == 27
        event_called = True

    manager = ComponentManager("manager")
    sound_effect = Component("sound_effect")
    manager.add_component(sound_effect)
    sound_effect.register_handlers({"event_name": event_call})

    assert sound_effect.has_handler("event_name")

    await sound_effect.raise_event(Event("event_name", 27))
    assert event_called

    event_called = False
    await manager.raise_event(Event("event_name", 27))
    assert event_called

    event_called = False
    manager.remove_component("sound_effect")
    with pytest.raises(AttributeError, match="No component manager bound for"):
        await sound_effect.raise_event(Event("event_name", 27))
    await manager.raise_event(Event("event_name", 27))
    assert not event_called


@pytest.mark.trio
async def test_raise_leveled_comes_back() -> None:
    event_called = False

    async def event_call(event: Event[int]) -> None:
        nonlocal event_called
        assert event.level == 0
        event_called = True

    event_called_two = False

    async def event_call_two(event: Event[int]) -> None:
        nonlocal event_called_two
        assert event.level == 0
        event_called_two = True

    super_manager = ComponentManager("super_manager")
    manager = ComponentManager("manager")

    super_manager.add_component(manager)
    assert super_manager.component_exists("manager")

    super_manager.register_handler("leveled_event", event_call)
    manager.register_handler("leveled_event", event_call_two)

    await manager.raise_event(Event("leveled_event", None, 1))
    assert event_called
    assert event_called_two


@pytest.mark.trio
async def test_raise_event_register_handler() -> None:
    event_called = False

    async def event_call(event: Event[int]) -> None:
        nonlocal event_called
        assert event.data == 27
        event_called = True

    manager = ComponentManager("manager")
    sound_effect = Component("sound_effect")
    manager.add_component(sound_effect)
    sound_effect.register_handler("event_name", event_call)

    await sound_effect.raise_event(Event("event_name", 27))
    assert event_called


@pytest.mark.trio
async def test_raises_event_in_nursery() -> None:
    nursery_called = False
    event_called = False

    async def call_bean(event: Event[None]) -> None:
        nonlocal event_called
        assert event.name == "bean_event"
        event_called = True

    async with trio.open_nursery() as nursery:
        original = nursery.start_soon

        def replacement(*args: object, **kwargs: object) -> object:
            nonlocal nursery_called
            nursery_called = True
            return original(*args, **kwargs)

        nursery.start_soon = replacement

        manager = ExternalRaiseManager("manager", nursery)
        manager.register_handler("bean_event", call_bean)
        await manager.raise_event(Event("bean_event", None))
    assert nursery_called
    assert event_called


@pytest.mark.trio
async def test_internal_does_not_raise_event_in_nursery() -> None:
    nursery_called = False
    event_called = False

    async def call_bean(event: Event[None]) -> None:
        nonlocal event_called
        assert event.name == "bean_event"
        event_called = True

    async with trio.open_nursery() as nursery:
        original = nursery.start_soon

        def replacement(*args: object, **kwargs: object) -> object:
            nonlocal nursery_called
            nursery_called = True
            return original(*args, **kwargs)

        nursery.start_soon = replacement

        manager = ExternalRaiseManager("manager", nursery)
        manager.register_handler("bean_event", call_bean)
        await manager.raise_event_internal(Event("bean_event", None))
    assert not nursery_called
    assert event_called


@pytest.mark.trio
async def test_temporary_component() -> None:
    event_called = False

    async def event_call(event: Event[int]) -> None:
        nonlocal event_called
        assert event.data == 27
        event_called = True

    manager = ComponentManager("manager")
    with manager.temporary_component(
        Component("sound_effect"),
    ) as sound_effect:
        assert manager.component_exists("sound_effect")
        sound_effect.register_handler("event_name", event_call)

        await sound_effect.raise_event(Event("event_name", 27))
        assert event_called
    assert not manager.component_exists("sound_effect")
    with manager.temporary_component(
        Component("sound_effect"),
    ) as sound_effect:
        manager.remove_component("sound_effect")


@pytest.mark.trio
async def test_remove_component() -> None:
    event_called = False

    async def event_call(event: Event[int]) -> None:
        nonlocal event_called
        assert event.data == 27
        event_called = True

    manager = ComponentManager("manager")
    sound_effect = Component("sound_effect")
    manager.add_component(sound_effect)
    assert manager.component_exists("sound_effect")
    sound_effect.register_handler("event_name", event_call)
    sound_effect.register_handler("waffle_name", event_call)

    await sound_effect.raise_event(Event("event_name", 27))
    assert event_called
    manager.add_component(Component("jerald"))
    manager.register_handler("event_name", event_call)
    manager.remove_component("jerald")
    manager.remove_component("sound_effect")
    assert not manager.component_exists("sound_effect")


def test_unregister_handler() -> None:
    async def event_call(event: Event[int]) -> None:
        return

    async def event_call2(event: Event[int]) -> None:
        return

    manager = ComponentManager("manager")
    sound_effect = Component("sound_effect")
    manager.add_component(sound_effect)
    assert manager.component_exists("sound_effect")
    sound_effect.register_handler("event_name", event_call)
    sound_effect.register_handler("event_name", event_call2)

    assert sound_effect.has_handler("event_name")

    sound_effect.unregister_handler("event_name", event_call)

    assert sound_effect.has_handler("event_name")

    sound_effect.unregister_handler("event_name", event_call2)

    assert not sound_effect.has_handler("event_name")


def test_unregister_handler_unregistered_failure() -> None:
    async def event_call(event: Event[int]) -> None:
        return

    manager = ComponentManager("manager")
    with pytest.raises(
        ValueError,
        match="^Component named 'cat' is not registered!$",
    ):
        manager.unregister_component_handler("event_name", event_call, "cat")


def test_unregister_handler_unregistered_handler_is_ok() -> None:
    async def event_call(event: Event[int]) -> None:
        return

    manager = ComponentManager("manager")
    manager.unregister_handler("event_name", event_call)


def test_unregister_handler_duplicate_type() -> None:
    async def event_call(event: Event[int]) -> None:
        return

    async def event_call2(event: Event[int]) -> None:
        return

    manager = ComponentManager("manager")
    manager.register_handler("event_name", event_call)

    manager.unregister_handler("event_name", event_call2)

    assert manager.has_handler("event_name")


def test_unregister_handler_type() -> None:
    async def event_call(event: Event[int]) -> None:
        return

    async def event_call2(event: Event[int]) -> None:
        return

    manager = ComponentManager("manager")
    sound_effect = Component("sound_effect")
    manager.add_component(sound_effect)
    assert manager.component_exists("sound_effect")
    sound_effect.register_handler("event_name", event_call)
    sound_effect.register_handler("event_name", event_call2)

    assert sound_effect.has_handler("event_name")

    sound_effect.unregister_handler_type("event_name")

    assert not sound_effect.has_handler("event_name")


def test_unregister_handler_type_unregistered_handler_is_ok() -> None:
    manager = ComponentManager("manager")
    manager.unregister_handler_type("event_name")
