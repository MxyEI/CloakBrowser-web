using CloakBrowser.Human;
using Microsoft.Playwright;

namespace CloakBrowser.Wrappers;

/// <summary>
/// Humanized actions that operate directly on an <see cref="ILocator"/>.
///
/// The selector-based <see cref="HumanPage"/> drives motion from a CSS/XPath selector;
/// locators don't expose their selector string publicly, so this helper drives the
/// same Bezier-curve / human-typing engine from the locator's own bounding box and
/// the shared <see cref="HumanCursor"/> state of the page it belongs to. The behavior
/// (curves, aim points, timing, typing stealth path) is identical to <see cref="HumanPage"/>;
/// only the element-resolution path differs.
/// </summary>
internal static class LocatorHumanizer
{
    private static double RemainingMs(double deadline) => CloakBrowser.Human.Actionability.RemainingMs(deadline);

    // When a selector string is known (from page.Locator(selector)), pre-click reads
    // go through the page's isolated world; otherwise they use Playwright's locator.

    private static async Task<BoundingBox?> GetBoxWorldAsync(IsolatedWorld world, string selector)
    {
        var (status, box) = await StealthDom.BoxAsync(world, selector).ConfigureAwait(false);
        return status == StealthStatus.Ok ? box : null;
    }

    private static async Task<BoundingBox?> GetBoxPlaywrightAsync(ILocator locator, double timeoutMs)
    {
        try
        {
            var box = await locator.First.BoundingBoxAsync(new LocatorBoundingBoxOptions
            {
                Timeout = (float)System.Math.Max(1, timeoutMs),
            }).ConfigureAwait(false);
            return box == null ? null : new BoundingBox(box.X, box.Y, box.Width, box.Height);
        }
        catch (System.Exception) { return null; }
    }

    private static async Task<bool> IsInputPlaywrightAsync(ILocator locator)
    {
        try
        {
            return await locator.First.EvaluateAsync<bool>(
                @"el => {
                    const tag = el.tagName.toLowerCase();
                    return tag === 'input' || tag === 'textarea'
                        || el.getAttribute('contenteditable') === 'true';
                }").ConfigureAwait(false);
        }
        catch (System.Exception) { return false; }
    }

    private static async Task<bool> IsFocusedAsync(ILocator locator, HumanCursor cursor, string? selector)
    {
        if (selector != null)
        {
            var world = await cursor.GetStealthAsync().ConfigureAwait(false);
            if (world != null)
            {
                var (status, value) = await StealthDom.IsFocusedAsync(world, selector).ConfigureAwait(false);
                if (status != StealthStatus.Unsupported) return value;
            }
        }
        try
        {
            return await locator.First.EvaluateAsync<bool>(
                "el => el === document.activeElement").ConfigureAwait(false);
        }
        catch (System.Exception) { return false; }
    }

    // Light isolated-world scroll: only wheels when the element is out of view, so an
    // already-visible element (the common case) needs no Playwright DOM op at all.
    private static async Task<BoundingBox?> EnsureInViewWorldAsync(
        HumanCursor cursor, IsolatedWorld world, string selector, BoundingBox box, HumanConfig cfg)
    {
        int vh = 0;
        try
        {
            var vp = await world.EvaluateAsync(StealthDom.ViewportJs).ConfigureAwait(false);
            if (vp != null && vp.Value.TryGetProperty("height", out var h)) vh = (int)h.GetDouble();
        }
        catch (System.Exception) { /* unknown viewport */ }
        if (vh == 0) return box;
        if (box.Y >= 0 && box.Y + box.Height <= vh) return box;

        double delta = (box.Y + box.Height / 2) - vh * 0.4;
        await HumanScroll.SmoothWheelAsync(cursor.RawMouse, 0, delta, cfg).ConfigureAwait(false);
        await HumanRandom.SleepMsAsync(HumanRandom.Rand(60, 140)).ConfigureAwait(false);
        var refreshed = await GetBoxWorldAsync(world, selector).ConfigureAwait(false);
        return refreshed ?? box;
    }

    // -----------------------------------------------------------------------
    // Core motion-to-target used by click/hover/dblclick.
    // -----------------------------------------------------------------------

    private static async Task<(double X, double Y, bool IsInput)> MoveToTargetAsync(
        ILocator locator, HumanCursor cursor, HumanConfig cfg, double deadline, bool force, string? selector)
    {
        await cursor.EnsureInitializedAsync(cfg).ConfigureAwait(false);

        if (cfg.IdleBetweenActions)
            await HumanMouse.HumanIdleAsync(cursor.RawMouse,
                HumanRandom.Rand(cfg.IdleBetweenDuration.Min, cfg.IdleBetweenDuration.Max),
                cursor.X, cursor.Y, cfg).ConfigureAwait(false);

        BoundingBox? box = null;
        bool isInput = false;
        bool resolved = false;

        if (selector != null)
        {
            var world = await cursor.GetStealthAsync().ConfigureAwait(false);
            if (world != null)
            {
                var (status, wbox) = await StealthDom.BoxAsync(world, selector).ConfigureAwait(false);
                if (status != StealthStatus.Unsupported)
                {
                    resolved = true; // world owns resolution (ok / not_found)
                    if (status == StealthStatus.Ok && wbox != null)
                    {
                        box = await EnsureInViewWorldAsync(cursor, world, selector, wbox.Value, cfg).ConfigureAwait(false);
                        isInput = (await StealthDom.IsInputAsync(world, selector).ConfigureAwait(false)).Value;
                    }
                }
            }
        }

        if (!resolved)
        {
            // Playwright path (selector unknown / unsupported / no world): scroll + read.
            if (!force)
                await locator.First.ScrollIntoViewIfNeededAsync(
                    new LocatorScrollIntoViewIfNeededOptions { Timeout = (float)RemainingMs(deadline) })
                    .ConfigureAwait(false);
            box = await GetBoxPlaywrightAsync(locator, RemainingMs(deadline)).ConfigureAwait(false);
            isInput = await IsInputPlaywrightAsync(locator).ConfigureAwait(false);
        }

        var target = HumanMouse.ClickTarget(
            box ?? new BoundingBox(cursor.X, cursor.Y, 1, 1), isInput, cfg);

        await HumanMouse.HumanMoveAsync(cursor.RawMouse, cursor.X, cursor.Y, target.X, target.Y, cfg)
            .ConfigureAwait(false);
        cursor.Set(target.X, target.Y);
        return (target.X, target.Y, isInput);
    }

    // -----------------------------------------------------------------------
    // Public humanized actions
    // -----------------------------------------------------------------------

    public static async Task ClickAsync(
        ILocator locator, HumanCursor cursor, HumanConfig cfg, double timeout, bool force, string? selector = null)
    {
        double deadline = System.Environment.TickCount64 + timeout;
        var t = await MoveToTargetAsync(locator, cursor, cfg, deadline, force, selector).ConfigureAwait(false);
        await HumanMouse.HumanClickAsync(cursor.RawMouse, t.IsInput, cfg).ConfigureAwait(false);
    }

    public static async Task DblClickAsync(
        ILocator locator, HumanCursor cursor, HumanConfig cfg, double timeout, bool force, string? selector = null)
    {
        double deadline = System.Environment.TickCount64 + timeout;
        await MoveToTargetAsync(locator, cursor, cfg, deadline, force, selector).ConfigureAwait(false);
        await cursor.RawMouseDownAsync(2).ConfigureAwait(false);
        await HumanRandom.SleepMsAsync(HumanRandom.Rand(30, 60)).ConfigureAwait(false);
        await cursor.RawMouseUpAsync(2).ConfigureAwait(false);
    }

    public static async Task HoverAsync(
        ILocator locator, HumanCursor cursor, HumanConfig cfg, double timeout, bool force, string? selector = null)
    {
        double deadline = System.Environment.TickCount64 + timeout;
        await MoveToTargetAsync(locator, cursor, cfg, deadline, force, selector).ConfigureAwait(false);
    }

    public static async Task TapAsync(
        ILocator locator, HumanCursor cursor, HumanConfig cfg, double timeout, bool force, string? selector = null) =>
        await ClickAsync(locator, cursor, cfg, timeout, force, selector).ConfigureAwait(false);

    public static async Task FillAsync(
        ILocator locator, HumanCursor cursor, HumanConfig cfg, double timeout, bool force, string value, string? selector = null)
    {
        double deadline = System.Environment.TickCount64 + timeout;
        await ClickAsync(locator, cursor, cfg, RemainingMs(deadline), force, selector).ConfigureAwait(false);
        await HumanRandom.SleepMsAsync(HumanRandom.Rand(100, 250)).ConfigureAwait(false);
        await cursor.SelectAllAsync().ConfigureAwait(false);
        await HumanRandom.SleepMsAsync(HumanRandom.Rand(30, 80)).ConfigureAwait(false);
        await cursor.PressAsync("Backspace").ConfigureAwait(false);
        await HumanRandom.SleepMsAsync(HumanRandom.Rand(50, 150)).ConfigureAwait(false);
        await cursor.HumanTypeAsync(value, cfg).ConfigureAwait(false);
    }

    public static async Task TypeAsync(
        ILocator locator, HumanCursor cursor, HumanConfig cfg, double timeout, bool force, string text, string? selector = null)
    {
        double deadline = System.Environment.TickCount64 + timeout;
        if (!await IsFocusedAsync(locator, cursor, selector).ConfigureAwait(false))
            await ClickAsync(locator, cursor, cfg, RemainingMs(deadline), force, selector).ConfigureAwait(false);
        await HumanRandom.SleepMsAsync(HumanRandom.Rand(100, 250)).ConfigureAwait(false);
        await cursor.HumanTypeAsync(text, cfg).ConfigureAwait(false);
    }

    public static async Task PressSequentiallyAsync(
        ILocator locator, HumanCursor cursor, HumanConfig cfg, double timeout, bool force, string text, string? selector = null) =>
        await TypeAsync(locator, cursor, cfg, timeout, force, text, selector).ConfigureAwait(false);

    public static async Task PressAsync(
        ILocator locator, HumanCursor cursor, HumanConfig cfg, double timeout, bool force,
        string key, float? delay = null, string? selector = null)
    {
        double deadline = System.Environment.TickCount64 + timeout;
        if (!await IsFocusedAsync(locator, cursor, selector).ConfigureAwait(false))
            await ClickAsync(locator, cursor, cfg, RemainingMs(deadline), force, selector).ConfigureAwait(false);
        await HumanRandom.SleepMsAsync(HumanRandom.Rand(50, 150)).ConfigureAwait(false);
        await cursor.PressAsync(key, delay).ConfigureAwait(false);
    }

    /// <summary>
    /// Human pre-roll for <c>select_option</c>: move the cursor along a Bezier curve to
    /// the &lt;select&gt; element (humanized hover) and pause, mirroring the Python
    /// <c>_humanized_select_option</c>. The real Playwright select call is performed by
    /// the caller afterwards (native &lt;select&gt; popups can't be driven by mouse).
    /// </summary>
    public static async Task SelectOptionPrologueAsync(
        ILocator locator, HumanCursor cursor, HumanConfig cfg, double timeout, bool force, string? selector = null)
    {
        await HoverAsync(locator, cursor, cfg, timeout, force, selector).ConfigureAwait(false);
        await HumanRandom.SleepMsAsync(HumanRandom.Rand(100, 300)).ConfigureAwait(false);
    }

    /// <summary>
    /// Human <c>clear</c>: focus the field (humanized click if not already focused),
    /// select-all, then press Backspace - instead of an instant value reset. Mirrors the
    /// Python <c>_humanized_clear</c>.
    /// </summary>
    public static async Task ClearAsync(
        ILocator locator, HumanCursor cursor, HumanConfig cfg, double timeout, bool force, string? selector = null)
    {
        double deadline = System.Environment.TickCount64 + timeout;
        if (!await IsFocusedAsync(locator, cursor, selector).ConfigureAwait(false))
            await ClickAsync(locator, cursor, cfg, RemainingMs(deadline), force, selector).ConfigureAwait(false);
        await HumanRandom.SleepMsAsync(HumanRandom.Rand(50, 100)).ConfigureAwait(false);
        await cursor.SelectAllAsync().ConfigureAwait(false);
        await HumanRandom.SleepMsAsync(HumanRandom.Rand(30, 80)).ConfigureAwait(false);
        await cursor.PressAsync("Backspace").ConfigureAwait(false);
    }
}
