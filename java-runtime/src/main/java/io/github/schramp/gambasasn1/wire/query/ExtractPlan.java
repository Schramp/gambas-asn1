package io.github.schramp.gambasasn1.wire.query;

import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Choice;
import io.github.schramp.gambasasn1.wire.spec.Asn1Contained;
import io.github.schramp.gambasasn1.wire.spec.Asn1Seq;
import io.github.schramp.gambasasn1.wire.spec.Asn1SeqOf;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import io.github.schramp.gambasasn1.wire.spec.Containing;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.spec.Positions;
import io.github.schramp.gambasasn1.wire.spec.SeqOf;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * A search plan for the values of some target types below a root type: the
 * root type's member graph, read from its tables, cut down to the members
 * that can lead to a target. A plan is compiled once per root type and
 * target set and can then run over any number of decoded values of that
 * type, one pass per value for all targets together.
 *
 * <p>A value matches a target when it is an instance of the target class;
 * the members it is reached through are those of its declared type. Every
 * occurrence is found: each element of a SEQUENCE OF, each present OPTIONAL
 * or extension member, the selected CHOICE alternative. Absent members,
 * unknown extensions, ANY and the bytes of a contained value that was not
 * decoded are not looked into; a decoded contained value is.
 */
public final class ExtractPlan {
    private static final Map<Key, ExtractPlan> CACHE = new ConcurrentHashMap<>();

    private record Key(Class<?> root, Set<Class<?>> targets) {
    }

    /** One step from a value to a member, alternative or element, and the plan below it. */
    private record Step(int index, String label, Node node) {
    }

    /** What to do at a value of one declared type. */
    private static final class Node {
        final String type;
        final Kind kind;
        /** The targets a value of this type is an instance of, in target order. */
        int[] hits = new int[0];
        List<Step> steps = new ArrayList<>();
        /** For a CHOICE: the step of each alternative, or null when it leads nowhere. */
        Step[] byAlt;
        boolean reaches;

        Node(String type, Kind kind) {
            this.type = type;
            this.kind = kind;
        }
    }

    private enum Kind { LEAF, SEQUENCE, CHOICE, SEQUENCE_OF, CONTAINED }

    private final Class<?> rootClass;
    private final List<Class<?>> targets;
    private final Node root;
    private final Map<Class<?>, Node> byClass;

    private ExtractPlan(AsMemberRef sample, List<Class<?>> targets) {
        this.rootClass = sample.getClass();
        this.targets = targets;
        Map<Class<?>, Node> named = new LinkedHashMap<>();
        List<Node> all = new ArrayList<>();
        this.root = build(sample.asMemberRef(), named, all);
        prune(all);
        this.byClass = named;
    }

    /**
     * The plan for {@code targets} below values of the type {@code root}
     * makes, from the cache when one was compiled before.
     *
     * @param root    makes a default value of the root type; only used to read its tables
     * @param targets the generated or runtime classes to look for
     */
    public static ExtractPlan of(Supplier<? extends AsMemberRef> root, Collection<Class<?>> targets) {
        AsMemberRef sample = root.get();
        List<Class<?>> list = List.copyOf(new LinkedHashSet<>(targets));
        return CACHE.computeIfAbsent(new Key(sample.getClass(), Set.copyOf(list)),
                k -> new ExtractPlan(sample, list));
    }

    /** {@link #of(Supplier, Collection)} for one target. */
    public static ExtractPlan of(Supplier<? extends AsMemberRef> root, Class<?> target) {
        return of(root, List.of(target));
    }

    /**
     * The plan for {@code targets} below values of {@code rootClass}, a
     * generated type (it has a public no-argument constructor).
     */
    public static ExtractPlan of(Class<? extends AsMemberRef> rootClass, Collection<Class<?>> targets) {
        List<Class<?>> list = List.copyOf(new LinkedHashSet<>(targets));
        return CACHE.computeIfAbsent(new Key(rootClass, Set.copyOf(list)),
                k -> new ExtractPlan(newInstance(rootClass), list));
    }

    private static AsMemberRef newInstance(Class<? extends AsMemberRef> c) {
        try {
            return c.getConstructor().newInstance();
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException
                 | InvocationTargetException e) {
            throw new IllegalArgumentException(c.getName() + " has no public no-argument constructor;"
                    + " compile the plan from a Supplier", e);
        }
    }

    /** The class whose values this plan runs over. */
    public Class<?> rootClass() {
        return rootClass;
    }

    /** The target classes, in the order given. */
    public List<Class<?>> targets() {
        return targets;
    }

    /** Whether a value of the root type can hold a value of any target at all. */
    public boolean canMatch() {
        return root.reaches;
    }

    /**
     * Runs the plan over {@code value}, of the root type or of any named
     * type below it; {@code positions} (may be null) gives each hit's offset.
     */
    public Extraction run(AsMemberRef value, Positions positions) {
        Node start = value.getClass() == rootClass ? root : byClass.get(value.getClass());
        if (start == null) {
            throw new IllegalArgumentException(value.getClass().getName() + " is not a type below "
                    + rootClass.getName() + " in this plan");
        }
        Extraction out = new Extraction(targets, positions);
        walk(start, value.asMemberRef(), out);
        return out;
    }

    /** {@link #run(AsMemberRef, Positions)} without positions. */
    public Extraction run(AsMemberRef value) {
        return run(value, null);
    }

    private static void walk(Node n, MemberRef m, Extraction out) {
        Object v = Positions.nodeOf(m);
        if (v == null) {
            return;
        }
        out.visited++;
        for (int t : n.hits) {
            out.add(t, v);
        }
        switch (n.kind) {
            case SEQUENCE -> {
                Asn1Seq s = (Asn1Seq) v;
                for (Step st : n.steps) {
                    walk(st.node, s.getMember(st.index), out);
                }
            }
            case CHOICE -> {
                Asn1Choice c = (Asn1Choice) v;
                int i = c.activeIndex();
                if (i >= 0 && i < n.byAlt.length && n.byAlt[i] != null) {
                    walk(n.byAlt[i].node, c.getActive(), out);
                }
            }
            case SEQUENCE_OF -> {
                if (!n.steps.isEmpty()) {
                    Node elem = n.steps.get(0).node;
                    Asn1SeqOf s = (Asn1SeqOf) v;
                    for (int i = 0, k = s.size(); i < k; i++) {
                        walk(elem, s.get(i), out);
                    }
                }
            }
            case CONTAINED -> {
                Asn1Contained c = (Asn1Contained) v;
                AsMemberRef inner = c.value();
                if (!n.steps.isEmpty() && inner != null && c.status() == ContainedStatus.DECODED) {
                    walk(n.steps.get(0).node, inner.asMemberRef(), out);
                }
            }
            case LEAF -> {
            }
        }
    }

    /**
     * The plan node of the type of {@code sample}, built from its tables:
     * a member's type is read from a default value the sample makes for it.
     * Named types are built once, so a recursive type closes into a cycle;
     * the generic SeqOf and Containing wrappers of inline types are built
     * per use, as their element or inner type differs per use.
     */
    private Node build(MemberRef sample, Map<Class<?>, Node> named, List<Node> all) {
        Object v = Positions.nodeOf(sample);
        Class<?> c = v.getClass();
        boolean generic = c == SeqOf.class || c == io.github.schramp.gambasasn1.wire.spec.SetOf.class
                || c == Containing.class;
        if (!generic) {
            Node done = named.get(c);
            if (done != null) {
                return done;
            }
        }
        Node n = switch (sample) {
            case MemberRef.Composite(var s) -> new Node(s.spec().name(), Kind.SEQUENCE);
            case MemberRef.Choice(var ch) -> new Node(ch.spec().name(), Kind.CHOICE);
            case MemberRef.SeqOf(var s) -> new Node(c.getSimpleName(), Kind.SEQUENCE_OF);
            case MemberRef.Contained(var s, var spec) -> new Node(c.getSimpleName(), Kind.CONTAINED);
            default -> new Node(c.getSimpleName(), Kind.LEAF);
        };
        if (!generic) {
            named.put(c, n);
        }
        all.add(n);
        List<Integer> hits = new ArrayList<>();
        for (int t = 0; t < targets.size(); t++) {
            if (targets.get(t).isInstance(v)) {
                hits.add(t);
            }
        }
        n.hits = hits.stream().mapToInt(Integer::intValue).toArray();
        switch (sample) {
            case MemberRef.Composite(var s) -> {
                for (int i = 0; i < s.spec().members().size(); i++) {
                    MemberRef m = s.presentMember(i);
                    if (Positions.nodeOf(m) != null) {
                        n.steps.add(new Step(i, s.spec().members().get(i).name(), build(m, named, all)));
                    }
                }
            }
            case MemberRef.Choice(var ch) -> {
                int count = ch.spec().alternatives().size();
                n.byAlt = new Step[count];
                for (int i = 0; i < count; i++) {
                    MemberRef m = ch.select(i);
                    if (Positions.nodeOf(m) != null) {
                        n.byAlt[i] = new Step(i, ch.spec().alternatives().get(i).name(), build(m, named, all));
                        n.steps.add(n.byAlt[i]);
                    }
                }
            }
            case MemberRef.SeqOf(var s) -> {
                MemberRef m = s.addDefault();
                if (Positions.nodeOf(m) != null) {
                    n.steps.add(new Step(0, "[*]", build(m, named, all)));
                }
            }
            case MemberRef.Contained(var s, var spec) -> {
                AsMemberRef inner = s.newInner();
                if (inner != null) {
                    n.steps.add(new Step(0, "(contents)", build(inner.asMemberRef(), named, all)));
                }
            }
            default -> {
            }
        }
        return n;
    }

    /** Marks the nodes that hit or lead to a hit, and drops the steps that lead nowhere. */
    private static void prune(List<Node> all) {
        for (Node n : all) {
            n.reaches = n.hits.length > 0;
        }
        boolean changed = true;
        while (changed) {
            changed = false;
            for (Node n : all) {
                if (!n.reaches && n.steps.stream().anyMatch(s -> s.node.reaches)) {
                    n.reaches = true;
                    changed = true;
                }
            }
        }
        for (Node n : all) {
            n.steps.removeIf(s -> !s.node.reaches);
            if (n.byAlt != null) {
                for (int i = 0; i < n.byAlt.length; i++) {
                    if (n.byAlt[i] != null && !n.byAlt[i].node.reaches) {
                        n.byAlt[i] = null;
                    }
                }
            }
        }
    }

    /**
     * The plan as text: one line per step that can lead to a target, as
     * member name and type name ({@code [*]} for the elements of a SEQUENCE
     * OF, {@code (contents)} for a contained value), each target the type
     * matches marked {@code *}; a type already shown is not expanded again.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        describe(root, "", 0, sb, new IdentityHashMap<>());
        return sb.toString();
    }

    private void describe(Node n, String label, int depth, StringBuilder sb, Map<Node, Boolean> shown) {
        sb.append("  ".repeat(depth)).append(label).append(n.type);
        for (int t : n.hits) {
            sb.append(" *").append(targets.get(t).getSimpleName());
        }
        if (shown.put(n, Boolean.TRUE) != null && !n.steps.isEmpty()) {
            sb.append(" ...\n");
            return;
        }
        sb.append('\n');
        for (Step s : n.steps) {
            describe(s.node, s.label + ": ", depth + 1, sb, shown);
        }
    }
}
