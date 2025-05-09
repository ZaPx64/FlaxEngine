// Copyright (c) Wojciech Figat. All rights reserved.

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using FlaxEditor.Scripting;
using FlaxEditor.Surface.Elements;
using FlaxEngine.Utilities;
using FlaxEngine;

namespace FlaxEditor.Surface.Archetypes
{
    /// <summary>
    /// Contains archetypes for nodes from the Packing group.
    /// </summary>
    [HideInEditor]
    public static class Packing
    {
        private class AppendNode : SurfaceNode
        {
            private InputBox _in0;
            private InputBox _in1;
            private OutputBox _out;

            /// <inheritdoc />
            public AppendNode(uint id, VisjectSurfaceContext context, NodeArchetype nodeArch, GroupArchetype groupArch)
            : base(id, context, nodeArch, groupArch)
            {
            }

            /// <inheritdoc />
            public override void OnSurfaceLoaded(SurfaceNodeActions action)
            {
                base.OnSurfaceLoaded(action);

                _in0 = (InputBox)GetBox(0);
                _in1 = (InputBox)GetBox(1);
                _out = (OutputBox)GetBox(2);

                _in0.CurrentTypeChanged += UpdateOutputType;
                _in1.CurrentTypeChanged += UpdateOutputType;

                UpdateOutputType(null);
            }

            private static int CountComponents(Type type)
            {
                if (type == typeof(bool) ||
                    type == typeof(char) ||
                    type == typeof(byte) ||
                    type == typeof(sbyte) ||
                    type == typeof(short) ||
                    type == typeof(ushort) ||
                    type == typeof(int) ||
                    type == typeof(uint) ||
                    type == typeof(long) ||
                    type == typeof(ulong) ||
                    type == typeof(float) ||
                    type == typeof(double))
                    return 1;
                if (type == typeof(Vector2) || type == typeof(Float2) || type == typeof(Double2))
                    return 2;
                if (type == typeof(Vector3) || type == typeof(Float3) || type == typeof(Double3))
                    return 3;
                if (type == typeof(Vector4) || type == typeof(Float4) || type == typeof(Double4) || type == typeof(Color))
                    return 4;
                return 0;
            }

            private void UpdateOutputType(Box box)
            {
                if (!_in0.HasAnyConnection || !_in1.HasAnyConnection)
                {
                    _out.CurrentType = ScriptType.Null;
                    return;
                }

                var count0 = CountComponents(_in0.CurrentType.Type);
                var count1 = CountComponents(_in1.CurrentType.Type);
                var count = count0 + count1;
                var outType = typeof(Float4);
                switch (count)
                {
                case 1:
                    outType = typeof(float);
                    break;
                case 2:
                    outType = typeof(Float2);
                    break;
                case 3:
                    outType = typeof(Float3);
                    break;
                case 4:
                    outType = typeof(Float4);
                    break;
                }
                _out.CurrentType = new ScriptType(outType);
            }
        }

        private abstract class StructureNode : SurfaceNode
        {
            private readonly bool _isUnpacking;

            /// <inheritdoc />
            protected StructureNode(uint id, VisjectSurfaceContext context, NodeArchetype nodeArch, GroupArchetype groupArch, bool isUnpacking)
            : base(id, context, nodeArch, groupArch)
            {
                _isUnpacking = isUnpacking;
            }

            /// <inheritdoc />
            public override void OnLoaded(SurfaceNodeActions action)
            {
                base.OnLoaded(action);

                // Update title and the tooltip
                var typeName = (string)Values[0];
                TooltipText = typeName;
                var type = TypeUtils.GetType(typeName);
                if (type)
                {
                    GetBox(0).CurrentType = type;
                    Title = (_isUnpacking ? "Unpack " : "Pack ") + type.Name;
                    TooltipText = SurfaceUtils.GetVisualScriptTypeDescription(type);
                }
                else
                {
                    Title = (_isUnpacking ? "Unpack " : "Pack ") + typeName;
                }

                // Update the boxes
                int fieldsLength;
                if (type)
                {
                    // Generate boxes for all structure fields
                    var fields = type.GetMembers(BindingFlags.Public | BindingFlags.Instance).Where(x => x.IsField).ToArray();
                    fieldsLength = fields.Length;
                    for (var i = 0; i < fieldsLength; i++)
                    {
                        var field = fields[i];
                        MakeBox(i + 1, field.Name, field.ValueType);
                    }

                    // Remove any not used boxes
                    for (int i = fieldsLength + 2; i < 32; i++)
                    {
                        var box = GetBox(i);
                        if (box == null)
                            break;
                        RemoveElement(box);
                    }

                    // Save structure layout
                    if (fieldsLength == 0)
                    {
                        // Skip allocations if structure is empty
                        Values[1] = Utils.GetEmptyArray<byte>();
                    }
                    else
                    {
                        using (var stream = new MemoryStream())
                        using (var writer = new BinaryWriter(stream))
                        {
                            writer.Write((byte)1); // Version
                            writer.Write(fieldsLength); // Fields count
                            for (int i = 0; i < fieldsLength; i++)
                            {
                                Utilities.Utils.WriteStr(writer, fields[i].Name, 11); // Field type
                                VariantUtils.WriteVariantType(writer, fields[i].ValueType); // Field type
                            }
                            Values[1] = stream.ToArray();
                        }
                    }
                }
                else if (Values[1] is byte[] data && data.Length != 0 && data[0] == 1)
                {
                    // Recreate node boxes based on the saved structure layout to preserve the connections
                    using (var stream = new MemoryStream(data))
                    using (var reader = new BinaryReader(stream))
                    {
                        reader.ReadByte(); // Version
                        fieldsLength = reader.ReadInt32(); // Fields count
                        for (int i = 0; i < fieldsLength; i++)
                        {
                            var fieldName = Utilities.Utils.ReadStr(reader, 11); // Field name
                            var fieldType = VariantUtils.ReadVariantType(reader); // Field type
                            MakeBox(i + 1, fieldName, new ScriptType(fieldType));
                        }
                    }
                }

                // Update node size
                ResizeAuto();
            }

            private void MakeBox(int id, string text, ScriptType type)
            {
                var box = GetBox(id);
                if (box == null)
                {
                    if (_isUnpacking)
                        box = new OutputBox(this, NodeElementArchetype.Factory.Output(id - 1, text, type, id));
                    else
                        box = new InputBox(this, NodeElementArchetype.Factory.Input(id - 1, text, true, type, id));
                    AddElement(box);
                }
            }
        }

        private sealed class PackStructureNode : StructureNode
        {
            /// <inheritdoc />
            public PackStructureNode(uint id, VisjectSurfaceContext context, NodeArchetype nodeArch, GroupArchetype groupArch)
            : base(id, context, nodeArch, groupArch, false)
            {
            }

            internal static bool IsInputCompatible(NodeArchetype nodeArch, ScriptType outputType, ConnectionsHint hint, VisjectSurfaceContext context)
            {
                var typeName = (string)nodeArch.DefaultValues[0];
                var type = TypeUtils.GetType(typeName);
                if (type)
                {
                    var fields = type.GetMembers(BindingFlags.Public | BindingFlags.Instance).Where(x => x.IsField).ToArray();
                    var fieldsLength = fields.Length;
                    for (var i = 0; i < fieldsLength; i++)
                    {
                        if (VisjectSurface.FullCastCheck(fields[i].ValueType, outputType, hint))
                            return true;
                    }
                }
                return false;
            }

            internal static bool IsOutputCompatible(NodeArchetype nodeArch, ScriptType inputType, ConnectionsHint hint, VisjectSurfaceContext context)
            {
                var typeName = (string)nodeArch.DefaultValues[0];
                var type = TypeUtils.GetType(typeName);
                if (type)
                {
                    if (VisjectSurface.FullCastCheck(type, inputType, hint))
                        return true;
                }
                return false;
            }

            internal static void GetInputOutputDescription(NodeArchetype nodeArch, out (string, ScriptType)[] inputs, out (string, ScriptType)[] outputs)
            {
                var typeName = (string)nodeArch.DefaultValues[0];
                var type = TypeUtils.GetType(typeName);
                if (type)
                {
                    var fields = type.GetMembers(BindingFlags.Public | BindingFlags.Instance).Where(x => x.IsField).ToArray();
                    var fieldsLength = fields.Length;
                    inputs = new (string, ScriptType)[fieldsLength];
                    for (var i = 0; i < fieldsLength; i++)
                    {
                        var field = fields[i];
                        inputs[i] = (field.Name, field.ValueType);
                    }

                    outputs = [(type.Name, type)];
                    return;
                }

                inputs = null;
                outputs = null;
            }
        }

        private sealed class UnpackStructureNode : StructureNode
        {
            /// <inheritdoc />
            public UnpackStructureNode(uint id, VisjectSurfaceContext context, NodeArchetype nodeArch, GroupArchetype groupArch)
            : base(id, context, nodeArch, groupArch, true)
            {
            }

            internal static bool IsInputCompatible(NodeArchetype nodeArch, ScriptType outputType, ConnectionsHint hint, VisjectSurfaceContext context)
            {
                var typeName = (string)nodeArch.DefaultValues[0];
                var type = TypeUtils.GetType(typeName);
                if (type)
                {
                    if (VisjectSurface.FullCastCheck(type, outputType, hint))
                        return true;
                }
                return false;
            }

            internal static bool IsOutputCompatible(NodeArchetype nodeArch, ScriptType inputType, ConnectionsHint hint, VisjectSurfaceContext context)
            {
                var typeName = (string)nodeArch.DefaultValues[0];
                var type = TypeUtils.GetType(typeName);
                if (type)
                {
                    var fields = type.GetMembers(BindingFlags.Public | BindingFlags.Instance).Where(x => x.IsField).ToArray();
                    var fieldsLength = fields.Length;
                    for (var i = 0; i < fieldsLength; i++)
                    {
                        if (VisjectSurface.FullCastCheck(fields[i].ValueType, inputType, hint))
                            return true;
                    }
                }
                return false;
            }
            
            internal static void GetInputOutputDescription(NodeArchetype nodeArch, out (string, ScriptType)[] inputs, out (string, ScriptType)[] outputs)
            {
                var typeName = (string)nodeArch.DefaultValues[0];
                var type = TypeUtils.GetType(typeName);
                if (type)
                {
                    inputs = [(type.Name, type)];

                    var fields = type.GetMembers(BindingFlags.Public | BindingFlags.Instance).Where(x => x.IsField).ToArray();
                    var fieldsLength = fields.Length;
                    outputs = new (string, ScriptType)[fieldsLength];
                    for (var i = 0; i < fieldsLength; i++)
                    {
                        var field = fields[i];
                        outputs[i] = (field.Name, field.ValueType);
                    }
                    return;
                }

                inputs = null;
                outputs = null;
            }
        }

        /// <summary>
        /// The nodes for that group.
        /// </summary>
        public static NodeArchetype[] Nodes =
        {
            // Packing
            new NodeArchetype
            {
                TypeID = 20,
                Title = "Pack Float2",
                Description = "Pack components to Float2",
                Flags = NodeFlags.AllGraphs,
                Size = new Float2(150, 40),
                DefaultValues = new object[]
                {
                    0.0f,
                    0.0f
                },
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Output(0, "Value", typeof(Float2), 0),
                    NodeElementArchetype.Factory.Input(0, "X", true, typeof(float), 1, 0),
                    NodeElementArchetype.Factory.Input(1, "Y", true, typeof(float), 2, 1),
                }
            },
            new NodeArchetype
            {
                TypeID = 21,
                Title = "Pack Float3",
                Description = "Pack components to Float3",
                Flags = NodeFlags.AllGraphs,
                Size = new Float2(150, 60),
                DefaultValues = new object[]
                {
                    0.0f,
                    0.0f,
                    0.0f
                },
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Output(0, "Value", typeof(Float3), 0),
                    NodeElementArchetype.Factory.Input(0, "X", true, typeof(float), 1, 0),
                    NodeElementArchetype.Factory.Input(1, "Y", true, typeof(float), 2, 1),
                    NodeElementArchetype.Factory.Input(2, "Z", true, typeof(float), 3, 2),
                }
            },
            new NodeArchetype
            {
                TypeID = 22,
                Title = "Pack Float4",
                Description = "Pack components to Float4",
                Flags = NodeFlags.AllGraphs,
                Size = new Float2(150, 80),
                DefaultValues = new object[]
                {
                    0.0f,
                    0.0f,
                    0.0f,
                    0.0f
                },
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Output(0, "Value", typeof(Float4), 0),
                    NodeElementArchetype.Factory.Input(0, "X", true, typeof(float), 1, 0),
                    NodeElementArchetype.Factory.Input(1, "Y", true, typeof(float), 2, 1),
                    NodeElementArchetype.Factory.Input(2, "Z", true, typeof(float), 3, 2),
                    NodeElementArchetype.Factory.Input(3, "W", true, typeof(float), 4, 3),
                }
            },
            new NodeArchetype
            {
                TypeID = 23,
                Title = "Pack Rotation",
                Description = "Pack components to Rotation",
                Flags = NodeFlags.AllGraphs,
                Size = new Float2(150, 60),
                DefaultValues = new object[]
                {
                    0.0f,
                    0.0f,
                    0.0f
                },
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Output(0, "Value", typeof(Quaternion), 0),
                    NodeElementArchetype.Factory.Input(0, "Pitch", true, typeof(float), 1, 0),
                    NodeElementArchetype.Factory.Input(1, "Yaw", true, typeof(float), 2, 1),
                    NodeElementArchetype.Factory.Input(2, "Roll", true, typeof(float), 3, 2),
                }
            },
            new NodeArchetype
            {
                TypeID = 24,
                Title = "Pack Transform",
                Description = "Pack components to Transform",
                Flags = NodeFlags.AllGraphs,
                Size = new Float2(150, 80),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Output(0, "Value", typeof(Transform), 0),
                    NodeElementArchetype.Factory.Input(0, "Translation", true, typeof(Vector3), 1),
                    NodeElementArchetype.Factory.Input(1, "Orientation", true, typeof(Quaternion), 2),
                    NodeElementArchetype.Factory.Input(2, "Scale", true, typeof(Float3), 3),
                }
            },
            new NodeArchetype
            {
                TypeID = 25,
                Title = "Pack Box",
                Description = "Pack components to BoundingBox",
                Flags = NodeFlags.AllGraphs,
                Size = new Float2(150, 40),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Output(0, "Value", typeof(BoundingBox), 0),
                    NodeElementArchetype.Factory.Input(0, "Minimum", true, typeof(Vector3), 1),
                    NodeElementArchetype.Factory.Input(1, "Maximum", true, typeof(Vector3), 2),
                }
            },
            new NodeArchetype
            {
                TypeID = 26,
                Title = "Pack Structure",
                Create = (id, context, arch, groupArch) => new PackStructureNode(id, context, arch, groupArch),
                IsInputCompatible = PackStructureNode.IsInputCompatible,
                IsOutputCompatible = PackStructureNode.IsOutputCompatible,
                GetInputOutputDescription = PackStructureNode.GetInputOutputDescription,
                Description = "Makes the structure data to from the components.",
                Flags = NodeFlags.VisualScriptGraph | NodeFlags.AnimGraph | NodeFlags.NoSpawnViaGUI,
                Size = new Float2(180, 20),
                DefaultValues = new object[]
                {
                    string.Empty, // Typename
                    Utils.GetEmptyArray<byte>(), // Cached structure layout data
                },
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Output(0, string.Empty, null, 0),
                }
            },
            // When adding more nodes here update logic in VisualScriptSurface to match the Pack/Unpack node archetypes indices

            // Unpacking
            new NodeArchetype
            {
                TypeID = 30,
                Title = "Unpack Float2",
                Description = "Unpack components from Float2",
                Flags = NodeFlags.AllGraphs,
                Size = new Float2(150, 40),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, typeof(Float2), 0),
                    NodeElementArchetype.Factory.Output(0, "X", typeof(float), 1),
                    NodeElementArchetype.Factory.Output(1, "Y", typeof(float), 2)
                }
            },
            new NodeArchetype
            {
                TypeID = 31,
                Title = "Unpack Float3",
                Description = "Unpack components from Float3",
                Flags = NodeFlags.AllGraphs,
                Size = new Float2(150, 60),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, typeof(Float3), 0),
                    NodeElementArchetype.Factory.Output(0, "X", typeof(float), 1),
                    NodeElementArchetype.Factory.Output(1, "Y", typeof(float), 2),
                    NodeElementArchetype.Factory.Output(2, "Z", typeof(float), 3)
                }
            },
            new NodeArchetype
            {
                TypeID = 32,
                Title = "Unpack Float4",
                Description = "Unpack components from Float4",
                Flags = NodeFlags.AllGraphs,
                Size = new Float2(150, 80),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, typeof(Float4), 0),
                    NodeElementArchetype.Factory.Output(0, "X", typeof(float), 1),
                    NodeElementArchetype.Factory.Output(1, "Y", typeof(float), 2),
                    NodeElementArchetype.Factory.Output(2, "Z", typeof(float), 3),
                    NodeElementArchetype.Factory.Output(3, "W", typeof(float), 4)
                }
            },
            new NodeArchetype
            {
                TypeID = 33,
                Title = "Unpack Rotation",
                Description = "Unpack components from Rotation",
                Flags = NodeFlags.AllGraphs,
                Size = new Float2(170, 60),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, typeof(Quaternion), 0),
                    NodeElementArchetype.Factory.Output(0, "Pitch", typeof(float), 1),
                    NodeElementArchetype.Factory.Output(1, "Yaw", typeof(float), 2),
                    NodeElementArchetype.Factory.Output(2, "Roll", typeof(float), 3)
                }
            },
            new NodeArchetype
            {
                TypeID = 34,
                Title = "Unpack Transform",
                Description = "Unpack components from Transform",
                Flags = NodeFlags.AllGraphs,
                Size = new Float2(170, 60),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, typeof(Transform), 0),
                    NodeElementArchetype.Factory.Output(0, "Translation", typeof(Vector3), 1),
                    NodeElementArchetype.Factory.Output(1, "Orientation", typeof(Quaternion), 2),
                    NodeElementArchetype.Factory.Output(2, "Scale", typeof(Float3), 3)
                }
            },
            new NodeArchetype
            {
                TypeID = 35,
                Title = "Unpack Box",
                Description = "Unpack components from BoundingBox",
                Flags = NodeFlags.AllGraphs,
                Size = new Float2(170, 40),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, typeof(BoundingBox), 0),
                    NodeElementArchetype.Factory.Output(0, "Minimum", typeof(Vector3), 1),
                    NodeElementArchetype.Factory.Output(1, "Maximum", typeof(Vector3), 2),
                }
            },
            new NodeArchetype
            {
                TypeID = 36,
                Title = "Unpack Structure",
                Create = (id, context, arch, groupArch) => new UnpackStructureNode(id, context, arch, groupArch),
                IsInputCompatible = UnpackStructureNode.IsInputCompatible,
                IsOutputCompatible = UnpackStructureNode.IsOutputCompatible,
                GetInputOutputDescription = UnpackStructureNode.GetInputOutputDescription,
                Description = "Breaks the structure data to allow extracting components from it.",
                Flags = NodeFlags.VisualScriptGraph | NodeFlags.AnimGraph | NodeFlags.NoSpawnViaGUI,
                Size = new Float2(180, 20),
                DefaultValues = new object[]
                {
                    string.Empty, // Typename
                    Utils.GetEmptyArray<byte>(), // Cached structure layout data
                },
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, string.Empty, true, null, 0),
                }
            },

            // Mask X,Y,Z,W
            new NodeArchetype
            {
                TypeID = 40,
                Title = "Mask X",
                Description = "Unpack X component from Vector",
                Flags = NodeFlags.AllGraphs,
                ConnectionsHints = ConnectionsHint.Vector,
                Size = new Float2(110, 30),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, null, 0),
                    NodeElementArchetype.Factory.Output(0, "X", typeof(float), 1)
                }
            },
            new NodeArchetype
            {
                TypeID = 41,
                Title = "Mask Y",
                Description = "Unpack Y component from Vector",
                Flags = NodeFlags.AllGraphs,
                ConnectionsHints = ConnectionsHint.Vector,
                Size = new Float2(110, 30),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, null, 0),
                    NodeElementArchetype.Factory.Output(0, "Y", typeof(float), 1)
                }
            },
            new NodeArchetype
            {
                TypeID = 42,
                Title = "Mask Z",
                Description = "Unpack Z component from Vector",
                Flags = NodeFlags.AllGraphs,
                ConnectionsHints = ConnectionsHint.Vector,
                Size = new Float2(110, 30),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, null, 0),
                    NodeElementArchetype.Factory.Output(0, "Z", typeof(float), 1)
                }
            },
            new NodeArchetype
            {
                TypeID = 43,
                Title = "Mask W",
                Description = "Unpack W component from Vector",
                Flags = NodeFlags.AllGraphs,
                ConnectionsHints = ConnectionsHint.Vector,
                Size = new Float2(110, 30),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, null, 0),
                    NodeElementArchetype.Factory.Output(0, "W", typeof(float), 1)
                }
            },

            // Mask XY, YZ, XZ,...
            new NodeArchetype
            {
                TypeID = 44,
                Title = "Mask XY",
                Description = "Unpack XY components from Vector",
                Flags = NodeFlags.AllGraphs,
                ConnectionsHints = ConnectionsHint.Vector,
                Size = new Float2(110, 30),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, null, 0),
                    NodeElementArchetype.Factory.Output(0, "XY", typeof(Float2), 1)
                }
            },
            new NodeArchetype
            {
                TypeID = 45,
                Title = "Mask XZ",
                Description = "Unpack XZ components from Vector",
                Flags = NodeFlags.AllGraphs,
                ConnectionsHints = ConnectionsHint.Vector,
                Size = new Float2(110, 30),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, null, 0),
                    NodeElementArchetype.Factory.Output(0, "XZ", typeof(Float2), 1)
                }
            },
            new NodeArchetype
            {
                TypeID = 46,
                Title = "Mask YZ",
                Description = "Unpack YZ components from Vector",
                Flags = NodeFlags.AllGraphs,
                ConnectionsHints = ConnectionsHint.Vector,
                Size = new Float2(110, 30),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, null, 0),
                    NodeElementArchetype.Factory.Output(0, "YZ", typeof(Float2), 1)
                }
            },
            new NodeArchetype
            {
                TypeID = 47,
                Title = "Mask ZW",
                Description = "Unpack ZW components from Vector",
                Flags = NodeFlags.AllGraphs,
                ConnectionsHints = ConnectionsHint.Vector,
                Size = new Float2(110, 30),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, null, 0),
                    NodeElementArchetype.Factory.Output(0, "ZW", typeof(Float2), 1)
                }
            },

            // Mask XYZ
            new NodeArchetype
            {
                TypeID = 70,
                Title = "Mask XYZ",
                Description = "Unpack XYZ components from Vector",
                Flags = NodeFlags.AllGraphs,
                ConnectionsHints = ConnectionsHint.Vector,
                Size = new Float2(110, 30),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, "Value", true, null, 0),
                    NodeElementArchetype.Factory.Output(0, "XYZ", typeof(Float3), 1)
                }
            },

            new NodeArchetype
            {
                TypeID = 100,
                Title = "Append",
                Description = "Appends vector or scalar value into vector",
                Create = (id, context, nodeArch, groupArch) => new AppendNode(id, context, nodeArch, groupArch),
                Flags = NodeFlags.AllGraphs,
                ConnectionsHints = ConnectionsHint.Numeric,
                Size = new Float2(140, 50),
                Elements = new[]
                {
                    NodeElementArchetype.Factory.Input(0, string.Empty, true, null, 0),
                    NodeElementArchetype.Factory.Input(1, string.Empty, true, null, 1),
                    NodeElementArchetype.Factory.Output(0, string.Empty, typeof(Float4), 2)
                }
            },
        };
    }
}
