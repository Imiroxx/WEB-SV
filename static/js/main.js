// Инициализация tooltips
function initTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');

    tooltips.forEach(tooltip => {
        const tooltipText = tooltip.dataset.tooltip;
        const tooltipElement = document.createElement('div');

        tooltipElement.className = 'hidden absolute z-50 bg-gray-800 text-white text-sm px-3 py-1 rounded-md shadow-lg';
        tooltipElement.textContent = tooltipText;
        tooltip.appendChild(tooltipElement);

        tooltip.addEventListener('mouseenter', () => {
            tooltipElement.classList.remove('hidden');
        });

        tooltip.addEventListener('mouseleave', () => {
            tooltipElement.classList.add('hidden');
        });
    });
}

// Инициализация модальных окон
function initModals() {
    const modalTriggers = document.querySelectorAll('[data-modal-target]');
    const modalCloses = document.querySelectorAll('[data-modal-close]');

    modalTriggers.forEach(trigger => {
        trigger.addEventListener('click', () => {
            const modalId = trigger.dataset.modalTarget;
            const modal = document.getElementById(modalId);
            modal.classList.remove('hidden');
        });
    });

    modalCloses.forEach(close => {
        close.addEventListener('click', () => {
            const modal = close.closest('.modal');
            modal.classList.add('hidden');
        });
    });
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    initTooltips();
    initModals();

    // Показать уведомления
    const notifications = document.querySelectorAll('.notification');
    notifications.forEach(notification => {
        setTimeout(() => {
            notification.classList.add('hidden');
        }, 5000);
    });

    // Инициализация табов
    const tabButtons = document.querySelectorAll('[data-tab-target]');
    const tabContents = document.querySelectorAll('[data-tab-content]');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const target = document.querySelector(button.dataset.tabTarget);

            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.add('hidden'));

            button.classList.add('active');
            target.classList.remove('hidden');
        });
    });

    // Активировать первый таб по умолчанию
    if (tabButtons.length > 0) {
        tabButtons[0].click();
    }
});
