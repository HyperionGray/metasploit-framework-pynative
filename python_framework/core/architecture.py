"""
Architecture improvements for Metasploit Framework

This module implements architectural improvements based on SOLID principles:
- Single Responsibility Principle
- Open/Closed Principle  
- Liskov Substitution Principle
- Interface Segregation Principle
- Dependency Inversion Principle

Design patterns implemented:
- Factory Pattern for object creation
- Observer Pattern for event handling
- Strategy Pattern for algorithm selection
- Command Pattern for operation encapsulation
- Dependency Injection for loose coupling
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Callable, Type, Protocol
from enum import Enum
import logging
from dataclasses import dataclass
import threading
import weakref


# Interfaces and Protocols (Interface Segregation Principle)

class Exploitable(Protocol):
    """Protocol for exploitable targets"""
    def check_vulnerability(self) -> bool: ...
    def exploit(self) -> Any: ...


class Configurable(Protocol):
    """Protocol for configurable components"""
    def set_option(self, name: str, value: Any) -> None: ...
    def get_option(self, name: str, default: Any = None) -> Any: ...


class Loggable(Protocol):
    """Protocol for components that support logging"""
    def log_info(self, message: str) -> None: ...
    def log_error(self, message: str) -> None: ...


class Auditable(Protocol):
    """Protocol for components that support auditing"""
    def audit_log(self, action: str, details: Dict[str, Any]) -> None: ...


# Abstract Base Classes (Dependency Inversion Principle)

class NetworkClient(ABC):
    """Abstract base class for network clients"""
    
    @abstractmethod
    def connect(self) -> bool:
        """Establish connection"""
        pass
    
    @abstractmethod
    def disconnect(self) -> None:
        """Close connection"""
        pass
    
    @abstractmethod
    def is_connected(self) -> bool:
        """Check connection status"""
        pass


class PayloadGenerator(ABC):
    """Abstract base class for payload generators"""
    
    @abstractmethod
    def generate(self, target_info: Dict[str, Any]) -> bytes:
        """Generate payload for target"""
        pass
    
    @abstractmethod
    def get_supported_platforms(self) -> List[str]:
        """Get list of supported platforms"""
        pass


class ExploitStrategy(ABC):
    """Abstract base class for exploit strategies"""
    
    @abstractmethod
    def execute(self, target: Any, payload: bytes) -> bool:
        """Execute exploit strategy"""
        pass
    
    @abstractmethod
    def get_requirements(self) -> Dict[str, Any]:
        """Get strategy requirements"""
        pass


# Factory Pattern Implementation

class ComponentFactory:
    """Factory for creating framework components"""
    
    _registry: Dict[str, Type] = {}
    
    @classmethod
    def register(cls, component_type: str, component_class: Type):
        """Register a component class"""
        cls._registry[component_type] = component_class
    
    @classmethod
    def create(cls, component_type: str, **kwargs) -> Any:
        """Create component instance"""
        if component_type not in cls._registry:
            raise ValueError(f"Unknown component type: {component_type}")
        
        component_class = cls._registry[component_type]
        return component_class(**kwargs)
    
    @classmethod
    def get_available_types(cls) -> List[str]:
        """Get list of available component types"""
        return list(cls._registry.keys())


# Observer Pattern Implementation

class Event:
    """Event data container"""
    def __init__(self, event_type: str, data: Dict[str, Any] = None):
        self.event_type = event_type
        self.data = data or {}
        self.timestamp = time.time()


class EventObserver(ABC):
    """Abstract observer for events"""
    
    @abstractmethod
    def handle_event(self, event: Event) -> None:
        """Handle an event"""
        pass


class EventPublisher:
    """Event publisher implementing observer pattern"""
    
    def __init__(self):
        self._observers: Dict[str, List[EventObserver]] = {}
        self._lock = threading.RLock()
    
    def subscribe(self, event_type: str, observer: EventObserver):
        """Subscribe observer to event type"""
        with self._lock:
            if event_type not in self._observers:
                self._observers[event_type] = []
            self._observers[event_type].append(observer)
    
    def unsubscribe(self, event_type: str, observer: EventObserver):
        """Unsubscribe observer from event type"""
        with self._lock:
            if event_type in self._observers:
                try:
                    self._observers[event_type].remove(observer)
                except ValueError:
                    pass
    
    def publish(self, event: Event):
        """Publish event to subscribers"""
        with self._lock:
            observers = self._observers.get(event.event_type, [])
            for observer in observers[:]:  # Copy to avoid modification during iteration
                try:
                    observer.handle_event(event)
                except Exception as e:
                    logging.getLogger(__name__).error(f"Observer error: {e}")


# Command Pattern Implementation

class Command(ABC):
    """Abstract command interface"""
    
    @abstractmethod
    def execute(self) -> Any:
        """Execute the command"""
        pass
    
    @abstractmethod
    def undo(self) -> Any:
        """Undo the command"""
        pass
    
    @abstractmethod
    def can_undo(self) -> bool:
        """Check if command can be undone"""
        pass


class CommandInvoker:
    """Command invoker with undo support"""
    
    def __init__(self, max_history: int = 100):
        self.max_history = max_history
        self._history: List[Command] = []
        self._current_index = -1
    
    def execute_command(self, command: Command) -> Any:
        """Execute a command and add to history"""
        result = command.execute()
        
        # Remove any commands after current index (for redo functionality)
        self._history = self._history[:self._current_index + 1]
        
        # Add command to history
        self._history.append(command)
        self._current_index += 1
        
        # Limit history size
        if len(self._history) > self.max_history:
            self._history.pop(0)
            self._current_index -= 1
        
        return result
    
    def undo(self) -> bool:
        """Undo the last command"""
        if self._current_index >= 0:
            command = self._history[self._current_index]
            if command.can_undo():
                command.undo()
                self._current_index -= 1
                return True
        return False
    
    def redo(self) -> bool:
        """Redo the next command"""
        if self._current_index + 1 < len(self._history):
            self._current_index += 1
            command = self._history[self._current_index]
            command.execute()
            return True
        return False


# Strategy Pattern Implementation

class StrategyContext:
    """Context for strategy pattern"""
    
    def __init__(self, strategy: Any = None):
        self._strategy = strategy
    
    def set_strategy(self, strategy: Any):
        """Set the strategy"""
        self._strategy = strategy
    
    def execute_strategy(self, *args, **kwargs) -> Any:
        """Execute the current strategy"""
        if not self._strategy:
            raise ValueError("No strategy set")
        return self._strategy.execute(*args, **kwargs)


# Dependency Injection Container

class DIContainer:
    """Dependency injection container"""
    
    def __init__(self):
        self._services: Dict[str, Any] = {}
        self._factories: Dict[str, Callable] = {}
        self._singletons: Dict[str, Any] = {}
        self._lock = threading.RLock()
    
    def register_instance(self, service_name: str, instance: Any):
        """Register a service instance"""
        with self._lock:
            self._services[service_name] = instance
    
    def register_factory(self, service_name: str, factory: Callable):
        """Register a service factory"""
        with self._lock:
            self._factories[service_name] = factory
    
    def register_singleton(self, service_name: str, factory: Callable):
        """Register a singleton service"""
        with self._lock:
            self._factories[service_name] = factory
            # Mark as singleton
            if service_name not in self._singletons:
                self._singletons[service_name] = None
    
    def resolve(self, service_name: str) -> Any:
        """Resolve a service"""
        with self._lock:
            # Check for direct instance
            if service_name in self._services:
                return self._services[service_name]
            
            # Check for singleton
            if service_name in self._singletons:
                if self._singletons[service_name] is None:
                    self._singletons[service_name] = self._factories[service_name]()
                return self._singletons[service_name]
            
            # Check for factory
            if service_name in self._factories:
                return self._factories[service_name]()
            
            raise ValueError(f"Service not registered: {service_name}")
    
    def is_registered(self, service_name: str) -> bool:
        """Check if service is registered"""
        return (service_name in self._services or 
                service_name in self._factories)


# Improved Base Classes with SOLID Principles

class BaseComponent:
    """Base component class following Single Responsibility Principle"""
    
    def __init__(self, name: str, logger: Optional[logging.Logger] = None):
        self.name = name
        self.logger = logger or logging.getLogger(f"{__name__}.{name}")
        self._initialized = False
    
    def initialize(self) -> bool:
        """Initialize the component"""
        if self._initialized:
            return True
        
        try:
            self._do_initialize()
            self._initialized = True
            self.logger.info(f"Component {self.name} initialized successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize component {self.name}: {e}")
            return False
    
    def _do_initialize(self):
        """Override in subclasses for specific initialization"""
        pass
    
    def cleanup(self):
        """Cleanup component resources"""
        if self._initialized:
            try:
                self._do_cleanup()
                self._initialized = False
                self.logger.info(f"Component {self.name} cleaned up")
            except Exception as e:
                self.logger.error(f"Error during cleanup of {self.name}: {e}")
    
    def _do_cleanup(self):
        """Override in subclasses for specific cleanup"""
        pass
    
    def is_initialized(self) -> bool:
        """Check if component is initialized"""
        return self._initialized


class ConfigurableComponent(BaseComponent):
    """Component with configuration support"""
    
    def __init__(self, name: str, config: Dict[str, Any] = None, **kwargs):
        super().__init__(name, **kwargs)
        self._config = config or {}
        self._config_validators: Dict[str, Callable] = {}
    
    def set_option(self, name: str, value: Any) -> None:
        """Set configuration option with validation"""
        if name in self._config_validators:
            validator = self._config_validators[name]
            if not validator(value):
                raise ValueError(f"Invalid value for option {name}: {value}")
        
        self._config[name] = value
        self.logger.debug(f"Set option {name} = {value}")
    
    def get_option(self, name: str, default: Any = None) -> Any:
        """Get configuration option"""
        return self._config.get(name, default)
    
    def register_validator(self, option_name: str, validator: Callable[[Any], bool]):
        """Register a validator for an option"""
        self._config_validators[option_name] = validator
    
    def get_config(self) -> Dict[str, Any]:
        """Get all configuration options"""
        return self._config.copy()


class ObservableComponent(ConfigurableComponent):
    """Component that can publish events"""
    
    def __init__(self, name: str, event_publisher: Optional[EventPublisher] = None, **kwargs):
        super().__init__(name, **kwargs)
        self.event_publisher = event_publisher or EventPublisher()
    
    def publish_event(self, event_type: str, data: Dict[str, Any] = None):
        """Publish an event"""
        event = Event(event_type, data)
        self.event_publisher.publish(event)
        self.logger.debug(f"Published event: {event_type}")


# Global instances
_global_di_container = DIContainer()
_global_event_publisher = EventPublisher()


def get_di_container() -> DIContainer:
    """Get global DI container"""
    return _global_di_container


def get_event_publisher() -> EventPublisher:
    """Get global event publisher"""
    return _global_event_publisher


# Decorators for architectural patterns

def injectable(service_name: str):
    """Decorator to mark a class as injectable"""
    def decorator(cls):
        _global_di_container.register_factory(service_name, cls)
        return cls
    return decorator


def singleton(service_name: str):
    """Decorator to mark a class as singleton"""
    def decorator(cls):
        _global_di_container.register_singleton(service_name, cls)
        return cls
    return decorator


def event_handler(event_type: str):
    """Decorator to register a method as event handler"""
    def decorator(func):
        # This would typically be used with a class that implements EventObserver
        func._event_type = event_type
        return func
    return decorator